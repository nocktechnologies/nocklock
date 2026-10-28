// Test-only helper: every operation targets the explicit disposable keychain.
// No default keychain/search-list setters, implicit searches or UI prompts.
#include <Security/Security.h>
#include <stdio.h>
#include <string.h>

static const char service[] = "nocklock-test";
static const char account[] = "fixture";
static const char canary[] = "SYNTHETIC-CANARY-ONLY";

int main(int argc, char **argv) {
    if (argc != 3 || argv[2][0] != '/' ||
        (strcmp(argv[1], "create") && strcmp(argv[1], "delete") &&
         strcmp(argv[1], "legacy") && strcmp(argv[1], "item"))) {
        return 64;
    }
    OSStatus status = SecKeychainSetUserInteractionAllowed(false);
    SecKeychainRef keychain = NULL;
    if (status != errSecSuccess) goto done;

    if (!strcmp(argv[1], "create")) {
        const char password[] = "synthetic-test-keychain-only";
        status = SecKeychainCreate(argv[2], sizeof(password) - 1, password,
                                   false, NULL, &keychain);
        if (status == errSecSuccess) {
            status = SecKeychainAddGenericPassword(keychain,
                sizeof(service) - 1, service, sizeof(account) - 1, account,
                sizeof(canary) - 1, canary, NULL);
        }
        goto done;
    }

    status = SecKeychainOpen(argv[2], &keychain);
    if (status != errSecSuccess) goto done;
    if (keychain == NULL) { status = errSecInvalidKeychain; goto done; }
    if (!strcmp(argv[1], "delete")) {
        status = SecKeychainDelete(keychain);
    } else if (!strcmp(argv[1], "legacy")) {
        UInt32 length = 0;
        void *data = NULL;
        status = SecKeychainFindGenericPassword(keychain,
            sizeof(service) - 1, service, sizeof(account) - 1, account,
            &length, &data, NULL);
        if (status == errSecSuccess) {
            fwrite(data, 1, length, stdout);
            SecKeychainItemFreeContent(NULL, data);
        }
    } else {
        const void *entry = keychain;
        CFArrayRef list = CFArrayCreate(NULL, &entry, 1, &kCFTypeArrayCallBacks);
        const void *keys[] = {kSecClass, kSecAttrService, kSecAttrAccount,
                              kSecMatchSearchList, kSecReturnData};
        const void *values[] = {kSecClassGenericPassword, CFSTR("nocklock-test"),
                                CFSTR("fixture"), list, kCFBooleanTrue};
        CFDictionaryRef query = CFDictionaryCreate(NULL, keys, values, 5,
            &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
        CFTypeRef result = NULL;
        status = SecItemCopyMatching(query, &result);
        if (status == errSecSuccess) {
            if (result == NULL || CFGetTypeID(result) != CFDataGetTypeID()) {
                status = errSecDecode;
            } else {
                fwrite(CFDataGetBytePtr(result), 1, CFDataGetLength(result), stdout);
            }
        }
        if (result) CFRelease(result);
        CFRelease(query);
        CFRelease(list);
    }
done:
    if (keychain) CFRelease(keychain);
    fprintf(stderr, "keychain-status=%d\n", (int)status);
    return status == errSecSuccess ? 0 : 1;
}
