#include <jni.h>
#include "include/dkls.h"
#include <string>
#include <cmath>
#include "jniCommon.cpp"

extern "C"
JNIEXPORT jint JNICALL
Java_com_web3auth_tss_1client_1android_dkls_Utilities_jniDklsBatchSize(JNIEnv *env,
                                                                       __attribute__((unused)) jclass clazz,jthrowable dkls_error) {
    int errorCode = 0;
    int *error_ptr = &errorCode;
    int result = dkls_batch_size(error_ptr);
    setErrorCode(env, dkls_error, errorCode);
    return result;
}

extern "C"
JNIEXPORT jstring JNICALL
Java_com_web3auth_tss_1client_1android_dkls_Utilities_jniDklsHashEncode(JNIEnv *env,
                                                                        __attribute__((unused)) jclass clazz,jstring msg,jthrowable dkls_error) {
    int errorCode = 0;
    int *error_ptr = &errorCode;
    const char *pMsg = env->GetStringUTFChars(msg, JNI_FALSE);
    const char* pResult = dkls_hash_encode(pMsg, error_ptr);
    env->ReleaseStringUTFChars(msg, pMsg);
    jstring result = env->NewStringUTF(pResult);
    dkls_string_free(const_cast<char*>(pResult));
    setErrorCode(env, dkls_error, errorCode);
    return result;
}


extern "C"
JNIEXPORT jstring JNICALL
Java_com_web3auth_tss_1client_1android_dkls_Utilities_jniDklsLocalSign(JNIEnv *env,
                                                                       __attribute__((unused)) jclass clazz, jstring msg, jboolean hash_only, jstring precompute,jthrowable dkls_error) {
    int errorCode = 0;
    int *error_ptr = &errorCode;
    const char *pPrecompute = env->GetStringUTFChars(precompute, JNI_FALSE);
    const char *pMsg = env->GetStringUTFChars(msg, JNI_FALSE);
    const char* pResult = dkls_local_sign(pMsg, hash_only, pPrecompute,  error_ptr);
    env->ReleaseStringUTFChars(msg, pMsg);
    env->ReleaseStringUTFChars(precompute, pPrecompute);
    jstring result = env->NewStringUTF(pResult);
    dkls_string_free(const_cast<char*>(pResult));
    setErrorCode(env, dkls_error, errorCode);
    return result;
}

extern "C"
JNIEXPORT jstring  JNICALL
Java_com_web3auth_tss_1client_1android_dkls_Utilities_jniDklsLocalVerify(JNIEnv *env,
                                                                         __attribute__((unused)) jclass clazz,jstring msg, jboolean hash_only, jstring r, jobject sig_frags, jstring pk, jthrowable dkls_error) {
    int errorCode = 0;
    int *error_ptr = &errorCode;

    jlong pFragments = GetPointerField(env, sig_frags);
    auto fragments = reinterpret_cast<Sigfrags *>(pFragments);
    const char *pR = env->GetStringUTFChars(r, JNI_FALSE);
    const char *pMsg = env->GetStringUTFChars(msg, JNI_FALSE);
    const char *pPubKey = env->GetStringUTFChars(pk, JNI_FALSE);
    const char* pResult = dkls_local_verify(pMsg, hash_only, pR, fragments, pPubKey, error_ptr);
    env->ReleaseStringUTFChars(pk, pPubKey);
    env->ReleaseStringUTFChars(msg, pMsg);
    env->ReleaseStringUTFChars(r, pR);
    jstring result = env->NewStringUTF(pResult);
    dkls_string_free(const_cast<char*>(pResult));
    setErrorCode(env, dkls_error, errorCode);
    return result;
}