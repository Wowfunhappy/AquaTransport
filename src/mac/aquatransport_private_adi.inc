/* Private CoreADI backend for Mavericks x86_64.
 *
 * CoreADI normally stores its machine identity below /Users/Shared/adi and
 * derives it from gethostuuid().  This backend redirects only those calls in
 * the short-lived AquaTransport worker.  The import table pages are made
 * copy-on-write, so Apple's binary, the dyld shared cache and other processes
 * are never changed or copied. */
#if __LP64__
#import <CoreServices/CoreServices.h>
#include <mach/mach.h>
#include <mach-o/fat.h>
#include <mach-o/loader.h>
#include <sys/mman.h>
#include <uuid/uuid.h>

#define AQ_PRIVATE_COREADI "/System/Library/PrivateFrameworks/CoreADI.framework/Versions/A/CoreADI"
#define AQ_PRIVATE_METADATA @"anisette-private.plist"

typedef struct {
    void *payload;
    uint32_t inputSize, outputSize, flags;
    unsigned char reserved[12];
} AQPrivateParams;

typedef struct {
    const char *name;
    const char *alias;
    const char *providerPrefix;
    void *original;
    void *replacement;
    unsigned matches;
} AQPrivateTarget;

typedef struct {
    uintptr_t *slot;
    uintptr_t encoded;
    void *replacement;
} AQPrivatePatch;

static int (*AQPrivateDispatch)(uint32_t, AQPrivateParams *);
static int (*AQPrivateOpen)(const char *, int, ...);
static int (*AQPrivateLstat)(const char *, struct stat *);
static int (*AQPrivateChmod)(const char *, mode_t);
static int (*AQPrivateMkdir)(const char *, mode_t);
static int (*AQPrivateHost)(uuid_t, const struct timespec *);
static OSStatus (*AQPrivatePathRef)(const UInt8 *, FSRef *, Boolean *);
static char AQPrivateRoot[PATH_MAX];
static uuid_t AQPrivateUUID;

static BOOL aq_private_error(NSError **error, NSString *message) {
    if (error) *error = aq_error(10, message);
    return NO;
}

static const char *aq_private_path(const char *path, char output[PATH_MAX]) {
    const char *prefix = "/Users/Shared/adi";
    size_t length = strlen(prefix);
    if (!path || strncmp(path, prefix, length) || (path[length] && path[length] != '/')) return path;
    if (snprintf(output, PATH_MAX, "%s/adi%s", AQPrivateRoot, path + length) >= PATH_MAX) {
        errno = ENAMETOOLONG;
        return NULL;
    }
    return output;
}

static int aq_private_open(const char *path, int flags, ...) {
    mode_t mode = 0;
    if (flags & O_CREAT) {
        va_list arguments;
        va_start(arguments, flags);
        mode = va_arg(arguments, int);
        va_end(arguments);
    }
    char redirected[PATH_MAX];
    path = aq_private_path(path, redirected);
    return path ? AQPrivateOpen(path, flags, mode) : -1;
}

static int aq_private_lstat(const char *path, struct stat *status) {
    char redirected[PATH_MAX];
    path = aq_private_path(path, redirected);
    return path ? AQPrivateLstat(path, status) : -1;
}

static int aq_private_chmod(const char *path, mode_t mode) {
    char redirected[PATH_MAX];
    path = aq_private_path(path, redirected);
    return path ? AQPrivateChmod(path, mode) : -1;
}

static int aq_private_mkdir(const char *path, mode_t mode) {
    char redirected[PATH_MAX];
    path = aq_private_path(path, redirected);
    return path ? AQPrivateMkdir(path, mode) : -1;
}

static int aq_private_host(uuid_t output, const struct timespec *timeout) {
    memcpy(output, AQPrivateUUID, sizeof AQPrivateUUID);
    return 0;
}

static OSStatus aq_private_path_ref(const UInt8 *path, FSRef *reference, Boolean *directory) {
    char redirected[PATH_MAX];
    const char *mapped = aq_private_path((const char *)path, redirected);
    return mapped ? AQPrivatePathRef((const UInt8 *)mapped, reference, directory) : fnfErr;
}

static BOOL aq_private_uuid(const struct mach_header_64 *header, unsigned char output[16]) {
    if (!header || header->magic != MH_MAGIC_64 || header->cputype != CPU_TYPE_X86_64) return NO;
    const unsigned char *cursor = (const void *)(header + 1);
    const unsigned char *end = cursor + header->sizeofcmds;
    if (end < cursor) return NO;
    for (uint32_t index = 0; index < header->ncmds; index++) {
        if (cursor > end || (size_t)(end - cursor) < sizeof(struct load_command)) return NO;
        const struct load_command *command = (const void *)cursor;
        if (command->cmdsize < sizeof(*command) || command->cmdsize > (size_t)(end - cursor)) return NO;
        if (command->cmd == LC_UUID && command->cmdsize >= sizeof(struct uuid_command)) {
            memcpy(output, ((const struct uuid_command *)command)->uuid, 16);
            return YES;
        }
        cursor += command->cmdsize;
    }
    return NO;
}

/* Return the x86_64 Mach-O slice without relying on a particular fat-image
 * offset. CoreADI has shipped as both a universal and a thin image. */
static BOOL aq_private_slice(const unsigned char *file, size_t length,
                             const unsigned char **slice, size_t *sliceLength) {
    if (length < sizeof(uint32_t)) return NO;
    uint32_t magic;
    memcpy(&magic, file, sizeof magic);
    if (magic == MH_MAGIC_64) {
        *slice = file;
        *sliceLength = length;
        return length >= sizeof(struct mach_header_64) &&
            ((const struct mach_header_64 *)file)->cputype == CPU_TYPE_X86_64;
    }
    if (magic != FAT_MAGIC && magic != FAT_CIGAM) return NO;
    if (length < sizeof(struct fat_header)) return NO;
    const struct fat_header *header = (const void *)file;
    BOOL swap = magic == FAT_CIGAM;
    uint32_t count = swap ? OSSwapInt32(header->nfat_arch) : header->nfat_arch;
    if (!count || count > 32 || length - sizeof(*header) < count * sizeof(struct fat_arch)) return NO;
    const struct fat_arch *architectures = (const void *)(header + 1);
    for (uint32_t index = 0; index < count; index++) {
        cpu_type_t type = swap ? (cpu_type_t)OSSwapInt32(architectures[index].cputype) : architectures[index].cputype;
        uint32_t offset = swap ? OSSwapInt32(architectures[index].offset) : architectures[index].offset;
        uint32_t size = swap ? OSSwapInt32(architectures[index].size) : architectures[index].size;
        if (type != CPU_TYPE_X86_64) continue;
        if (offset > length || size > length - offset || size < sizeof(struct mach_header_64)) return NO;
        *slice = file + offset;
        *sliceLength = size;
        return ((const struct mach_header_64 *)*slice)->magic == MH_MAGIC_64;
    }
    return NO;
}

/* A CoreServices reexport can legitimately give CoreADI and this executable
 * different callable addresses for the same API. Identify the exact symbol
 * from its expected system provider, with direct equality as a fallback for
 * stripped libSystem symbols. */
static BOOL aq_private_target_matches(const AQPrivateTarget *target, uintptr_t resolved) {
    Dl_info symbol;
    if (dladdr((void *)resolved, &symbol) && symbol.dli_fname && symbol.dli_sname &&
        symbol.dli_saddr && (uintptr_t)symbol.dli_saddr == resolved &&
        !strncmp(symbol.dli_fname, target->providerPrefix, strlen(target->providerPrefix)) &&
        (!strcmp(symbol.dli_sname, target->name) ||
         (target->alias && !strcmp(symbol.dli_sname, target->alias)))) return YES;
    return resolved == (uintptr_t)target->original;
}

/* CoreADI 2.x stores encoded imports in its writable data rather than normal
 * Mach-O symbol-pointer sections. For each word, the unrelocated on-disk value
 * is the encoding addend and the loaded value is addend + resolved function.
 * Comparing both images lets us discover the slots at runtime, so this does not
 * depend on one Mac's dyld pathname, shared-cache layout, offsets or addends. */
static BOOL aq_private_patch(const struct mach_header_64 *loaded, const char *path, NSError **error) {
    int descriptor = open(path, O_RDONLY | O_CLOEXEC);
    if (descriptor < 0) return aq_private_error(error, @"Apple's native device authentication image could not be read.");
    struct stat status;
    if (fstat(descriptor, &status) || status.st_size < (off_t)sizeof(struct mach_header_64) ||
        status.st_size > 64 * 1024 * 1024) {
        close(descriptor);
        return aq_private_error(error, @"Apple's native device authentication image has an invalid size.");
    }
    size_t fileLength = (size_t)status.st_size;
    const unsigned char *file = mmap(NULL, fileLength, PROT_READ, MAP_PRIVATE, descriptor, 0);
    close(descriptor);
    if (file == MAP_FAILED) return aq_private_error(error, @"Apple's native device authentication image could not be mapped.");

    BOOL result = NO;
    const unsigned char *slice = NULL;
    size_t sliceLength = 0;
    unsigned char loadedUUID[16], fileUUID[16];
    if (!aq_private_slice(file, fileLength, &slice, &sliceLength) ||
        !aq_private_uuid(loaded, loadedUUID) ||
        !aq_private_uuid((const struct mach_header_64 *)slice, fileUUID) ||
        memcmp(loadedUUID, fileUUID, sizeof loadedUUID)) {
        aq_private_error(error, @"The loaded and installed Apple device authentication images do not match. Restart this Mac after system updates.");
        goto finished;
    }

    AQPrivateTarget targets[] = {
        {"FSPathMakeRef", "_FSPathMakeRef", "/System/Library/Frameworks/CoreServices.framework/",
            (void *)AQPrivatePathRef, (void *)aq_private_path_ref, 0},
        {"chmod", "_chmod", "/usr/lib/", (void *)AQPrivateChmod, (void *)aq_private_chmod, 0},
        {"gethostuuid", "_gethostuuid", "/usr/lib/", (void *)AQPrivateHost, (void *)aq_private_host, 0},
        {"lstat$INODE64", "lstat", "/usr/lib/", (void *)AQPrivateLstat, (void *)aq_private_lstat, 0},
        {"mkdir", "_mkdir", "/usr/lib/", (void *)AQPrivateMkdir, (void *)aq_private_mkdir, 0},
        {"open", "__open", "/usr/lib/", (void *)AQPrivateOpen, (void *)aq_private_open, 0}
    };
    AQPrivatePatch patches[64];
    size_t patchCount = 0;
    const struct mach_header_64 *header = (const void *)slice;
    const unsigned char *cursor = (const void *)(header + 1);
    const unsigned char *end = cursor + header->sizeofcmds;
    if (header->sizeofcmds > sliceLength - sizeof(*header) || end < cursor) {
        aq_private_error(error, @"Apple's native device authentication image has invalid load commands.");
        goto finished;
    }

    uint64_t imageVMAddress = UINT64_MAX;
    for (uint32_t index = 0; index < header->ncmds; index++) {
        if (cursor > end || (size_t)(end - cursor) < sizeof(struct load_command)) break;
        const struct load_command *command = (const void *)cursor;
        if (command->cmdsize < sizeof(*command) || command->cmdsize > (size_t)(end - cursor)) break;
        if (command->cmd == LC_SEGMENT_64 && command->cmdsize >= sizeof(struct segment_command_64)) {
            const struct segment_command_64 *segment = (const void *)command;
            if (!segment->fileoff && segment->filesize && segment->vmaddr < imageVMAddress) imageVMAddress = segment->vmaddr;
        }
        cursor += command->cmdsize;
    }
    if (imageVMAddress == UINT64_MAX) {
        aq_private_error(error, @"Apple's native device authentication image has no loadable base segment.");
        goto finished;
    }
    uintptr_t slide = (uintptr_t)loaded - (uintptr_t)imageVMAddress;

    cursor = (const void *)(header + 1);
    for (uint32_t index = 0; index < header->ncmds; index++) {
        if (cursor > end || (size_t)(end - cursor) < sizeof(struct load_command)) break;
        const struct load_command *command = (const void *)cursor;
        if (command->cmdsize < sizeof(*command) || command->cmdsize > (size_t)(end - cursor)) break;
        if (command->cmd == LC_SEGMENT_64 && command->cmdsize >= sizeof(struct segment_command_64)) {
            const struct segment_command_64 *segment = (const void *)command;
            if ((!strncmp(segment->segname, SEG_DATA, 16) || !strncmp(segment->segname, "__DATA_CONST", 16)) &&
                segment->nsects <= (command->cmdsize - sizeof(*segment)) / sizeof(struct section_64)) {
                const struct section_64 *sections = (const void *)(segment + 1);
                for (uint32_t sectionIndex = 0; sectionIndex < segment->nsects; sectionIndex++) {
                    const struct section_64 *section = sections + sectionIndex;
                    uint32_t type = section->flags & SECTION_TYPE;
                    if (type == S_ZEROFILL || type == S_GB_ZEROFILL || section->offset > sliceLength ||
                        section->size > sliceLength - section->offset) continue;
                    for (uint64_t offset = 0; offset + sizeof(uintptr_t) <= section->size; offset += sizeof(uintptr_t)) {
                        uintptr_t encoded, value;
                        memcpy(&encoded, slice + section->offset + offset, sizeof encoded);
                        uintptr_t *slot = (void *)(slide + (uintptr_t)section->addr + (uintptr_t)offset);
                        memcpy(&value, slot, sizeof value);
                        for (size_t target = 0; target < sizeof targets / sizeof targets[0]; target++) {
                            if (!aq_private_target_matches(&targets[target], value - encoded)) continue;
                            if (patchCount == sizeof patches / sizeof patches[0]) {
                                aq_private_error(error, @"Apple's native device authentication import table is ambiguous.");
                                goto finished;
                            }
                            patches[patchCount].slot = slot;
                            patches[patchCount].encoded = encoded;
                            patches[patchCount].replacement = targets[target].replacement;
                            patchCount++;
                            targets[target].matches++;
                        }
                    }
                }
            }
        }
        cursor += command->cmdsize;
    }

    for (size_t target = 0; target < sizeof targets / sizeof targets[0]; target++) {
        if (!targets[target].matches) {
            aq_private_error(error, [NSString stringWithFormat:
                @"Apple's native device authentication import for %s could not be isolated.", targets[target].name]);
            goto finished;
        }
    }
    for (size_t patch = 0; patch < patchCount; patch++) {
        vm_size_t pageSize = vm_page_size;
        vm_address_t page = (vm_address_t)patches[patch].slot & ~(vm_address_t)(pageSize - 1);
        if (vm_protect(mach_task_self(), page, pageSize, FALSE,
                       VM_PROT_READ | VM_PROT_WRITE | VM_PROT_COPY) != KERN_SUCCESS) {
            aq_private_error(error, @"Apple's native device authentication imports could not be made process-private.");
            goto finished;
        }
    }
    for (size_t patch = 0; patch < patchCount; patch++)
        *patches[patch].slot = (uintptr_t)patches[patch].replacement + patches[patch].encoded;
    result = YES;

finished:
    munmap((void *)file, fileLength);
    return result;
}

static void aq_private_u32(NSMutableData *data, uint32_t value) {
    value = htonl(value);
    [data appendBytes:&value length:sizeof value];
}

static void aq_private_u64(NSMutableData *data, uint64_t value) {
    value = OSSwapHostToBigInt64(value);
    [data appendBytes:&value length:sizeof value];
}

static int aq_private_call(uint32_t code, NSData *message) {
    NSMutableData *packet = [NSMutableData dataWithLength:MAX(2048, 8 + [message length])];
    unsigned char *payload = [packet mutableBytes];
    payload[3] = payload[7] = 1;
    memcpy(payload + 8, [message bytes], [message length]);
    AQPrivateParams parameters = {payload, (uint32_t)(8 + [message length]), 4, 0, {0}};
    int result = AQPrivateDispatch(code, &parameters);
    int32_t status;
    memcpy(&status, payload, sizeof status);
    return result < 0 ? result : (int32_t)ntohl(status);
}

static int aq_private_state(uint64_t dsid) {
    NSMutableData *data = [NSMutableData data];
    aq_private_u64(data, dsid);
    return aq_private_call(0xb0eda7af, data);
}

static int aq_private_otp(uint64_t dsid, void **mid, uint32_t *midLength, void **otp, uint32_t *otpLength) {
    NSMutableData *data = [NSMutableData data];
    aq_private_u64(data, dsid);
    aq_private_u64(data, (uintptr_t)mid);
    aq_private_u64(data, (uintptr_t)midLength);
    aq_private_u64(data, (uintptr_t)otp);
    aq_private_u64(data, (uintptr_t)otpLength);
    return aq_private_call(0xcfe0b46a, data);
}

static int aq_private_start(uint64_t dsid, const void *spim, uint32_t spimLength,
                            void **cpim, uint32_t *cpimLength, uint32_t *session) {
    NSMutableData *data = [NSMutableData data];
    aq_private_u64(data, dsid);
    aq_private_u64(data, (uintptr_t)spim);
    aq_private_u32(data, spimLength);
    aq_private_u64(data, (uintptr_t)cpim);
    aq_private_u64(data, (uintptr_t)cpimLength);
    aq_private_u64(data, (uintptr_t)session);
    return aq_private_call(0x716bd86c, data);
}

static int aq_private_finish(uint32_t session, const void *ptm, uint32_t ptmLength,
                             const void *token, uint32_t tokenLength) {
    NSMutableData *data = [NSMutableData data];
    aq_private_u32(data, session);
    aq_private_u64(data, (uintptr_t)ptm);
    aq_private_u32(data, ptmLength);
    aq_private_u64(data, (uintptr_t)token);
    aq_private_u32(data, tokenLength);
    return aq_private_call(0x0b2b3196, data);
}

static int aq_private_destroy(uint32_t session) {
    NSMutableData *data = [NSMutableData data];
    aq_private_u32(data, session);
    return aq_private_call(0x55a637c0, data);
}

static int aq_private_dispose(void *value) {
    NSMutableData *data = [NSMutableData data];
    aq_private_u64(data, (uintptr_t)value);
    return aq_private_call(0x3e58e7f9, data);
}

static int aq_private_sync(uint64_t dsid, const void *server, uint32_t serverLength,
                           void **mid, uint32_t *midLength, void **srm, uint32_t *srmLength) {
    NSMutableData *data = [NSMutableData data];
    aq_private_u64(data, dsid);
    aq_private_u64(data, (uintptr_t)server);
    aq_private_u32(data, serverLength);
    aq_private_u64(data, (uintptr_t)mid);
    aq_private_u64(data, (uintptr_t)midLength);
    aq_private_u64(data, (uintptr_t)srm);
    aq_private_u64(data, (uintptr_t)srmLength);
    return aq_private_call(0xa54951ec, data);
}

static BOOL aq_private_directory(NSString *path, NSError **error) {
    const char *file = [path fileSystemRepresentation];
    struct stat status;
    if ((mkdir(file, 0700) && errno != EEXIST) || lstat(file, &status) ||
        !S_ISDIR(status.st_mode) || status.st_uid != geteuid())
        return aq_private_error(error, @"The private device authentication directory could not be prepared securely.");
    if ((status.st_mode & 077) && (chmod(file, 0700) || lstat(file, &status) || (status.st_mode & 077)))
        return aq_private_error(error, @"The private device authentication directory permissions could not be secured.");
    return YES;
}

static BOOL aq_private_load(NSString *device, NSError **error) {
    static BOOL loaded, failed;
    if (loaded) return YES;
    if (failed) return aq_private_error(error, @"Private native device authentication initialization previously failed in this worker.");
    if (!device || uuid_parse([device UTF8String], AQPrivateUUID)) {
        failed = YES;
        return aq_private_error(error, @"The private device authentication identifier is invalid.");
    }
    NSString *base = [NSHomeDirectory() stringByAppendingPathComponent:
        @"Library/Application Support/AquaTransport/CoreADI-private"];
    if (!aq_private_directory(base, error) ||
        !aq_private_directory([base stringByAppendingPathComponent:@"adi"], error)) {
        failed = YES;
        return NO;
    }
    strlcpy(AQPrivateRoot, [base fileSystemRepresentation], sizeof AQPrivateRoot);
    AQPrivateOpen = open;
    AQPrivateLstat = lstat;
    AQPrivateChmod = chmod;
    AQPrivateMkdir = mkdir;
    AQPrivateHost = gethostuuid;
    AQPrivatePathRef = FSPathMakeRef;

    void *handle = dlopen(AQ_PRIVATE_COREADI, RTLD_NOW | RTLD_LOCAL);
    if (!handle) {
        failed = YES;
        return aq_private_error(error, @"Apple's native device authentication framework could not be loaded.");
    }
    AQPrivateDispatch = dlsym(handle, "vdfut768ig");
    int (*interfaceInfo)(uint32_t *) = dlsym(handle, "cvu8io98wun");
    Dl_info image;
    uint32_t interface[3] = {0};
    if (!AQPrivateDispatch || !interfaceInfo || interfaceInfo(interface) ||
        interface[0] != 1 || interface[1] != sizeof(AQPrivateParams) ||
        !dladdr((void *)AQPrivateDispatch, &image) || !image.dli_fbase) {
        failed = YES;
        return aq_private_error(error, @"Apple's native device authentication framework has an incompatible interface.");
    }
    if (!aq_private_patch((const struct mach_header_64 *)image.dli_fbase, AQ_PRIVATE_COREADI, error)) {
        failed = YES;
        return NO;
    }
    int initialized = aq_private_call(0x12db31c5, [NSData data]);
    if (initialized != 1) {
        failed = YES;
        return aq_private_error(error, [NSString stringWithFormat:
            @"Apple's private device authentication framework could not initialize (status %d).", initialized]);
    }
    AQADI.otp = aq_private_otp;
    AQADI.sync = aq_private_sync;
    AQADI.start = aq_private_start;
    AQADI.finish = aq_private_finish;
    AQADI.destroy = aq_private_destroy;
    AQADI.dispose = aq_private_dispose;
    AQADI.state = aq_private_state;
    loaded = YES;
    return YES;
}

static BOOL aq_private_preferred(void) {
    NSDictionary *system = [NSDictionary dictionaryWithContentsOfFile:
        @"/System/Library/CoreServices/SystemVersion.plist"];
    return [[[system objectForKey:@"ProductVersion"] description] isEqual:@"10.9.5"] &&
        !access(AQ_PRIVATE_COREADI, R_OK);
}
#endif
