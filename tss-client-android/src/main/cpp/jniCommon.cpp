#include <jni.h>
#include "include/dkls.h"
#include <string>
#include <cmath>

#define LOG_TAG "DKLS"

#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR,    LOG_TAG, __VA_ARGS__)
#define LOGW(...) __android_log_print(ANDROID_LOG_WARN,     LOG_TAG, __VA_ARGS__)
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO,     LOG_TAG, __VA_ARGS__)
#define LOGD(...) __android_log_print(ANDROID_LOG_DEBUG,    LOG_TAG, __VA_ARGS__)

inline jbyteArray getBytesFromUnsignedLongLong(JNIEnv *jEnv, unsigned long long int value) {
    const size_t size = sizeof(unsigned long long int);
    jbyteArray result = jEnv->NewByteArray((jsize) size);
    if (result != nullptr) {
        jbyte *cBytes = jEnv->GetByteArrayElements(result, nullptr);
        if (cBytes != nullptr) {
            int i;
            for (i = (int) (size - 1); i >= 0; i--) {
                cBytes[i] = (jbyte) (value & 0xFF);
                value >>= 8;
            }
            jEnv->ReleaseByteArrayElements(result, cBytes, 0);
        }
    }
    return result;
}

inline jmethodID
getMethodId(JNIEnv *jniEnv, jobject jThis, jstring methodName, jstring methodSignature) {
    auto jClass = jniEnv->GetObjectClass(jThis);
    const char *method = jniEnv->GetStringUTFChars(methodName, JNI_FALSE);
    const char *signature = jniEnv->GetStringUTFChars(methodSignature, JNI_FALSE);
    auto methodId = jniEnv->GetMethodID(jClass, method, signature);
    jniEnv->ReleaseStringUTFChars(methodSignature, signature);
    jniEnv->ReleaseStringUTFChars(methodName, method);
    return methodId;
}

inline jlong GetPointerField(JNIEnv *jEnv, jobject jThis, const char* fieldId = "pointer") {
    auto cls = jEnv->GetObjectClass(jThis);
    auto fid = jEnv->GetFieldID(cls, fieldId, "J");
    jlong lObject = jEnv->GetLongField(jThis, fid);
    return lObject;
}


inline void SetPointerField(JNIEnv *jEnv, jobject jThis, jlong jPointer, const char* fieldId = "pointer") {
    auto cls = jEnv->GetObjectClass(jThis);
    auto fid = jEnv->GetFieldID(cls, fieldId, "J");
    jEnv->SetLongField(jThis, fid, jPointer);
}


inline jboolean setErrorCode(JNIEnv *jEnv, jobject error, jint value) {
    jclass errorClass = jEnv->GetObjectClass(error);
    if (errorClass == nullptr)
        return static_cast<jboolean>(false);
    jfieldID errorField = jEnv->GetFieldID(errorClass, "code", "I");
    if (errorField == nullptr)
        return static_cast<jboolean>(false);
    jEnv->SetIntField(error, errorField, value);
    return static_cast<jboolean>(true);
}