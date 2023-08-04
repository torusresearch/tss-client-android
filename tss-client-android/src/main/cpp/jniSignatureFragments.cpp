//
// Created by grvgo on 28-07-2023.
//
#include <jni.h>
#include "include/dkls.h"
#include <string>
#include <cmath>
#include "jniCommon.cpp"


extern "C"
JNIEXPORT jlong JNICALL
Java_com_web3auth_tss_1client_1android_dkls_SignatureFragments_jniSignatureFragmentsFromString(
        JNIEnv *env, jobject thiz, jstring input, jthrowable dkls_error) {
    int errorCode = 0;
    int *error_ptr = &errorCode;
    const char *pInput = env->GetStringUTFChars(input, JNI_FALSE);
    auto *pResult = signature_fragments_from_string(pInput, error_ptr);
    env->ReleaseStringUTFChars(input, pInput);
    setErrorCode(env, dkls_error, errorCode);
    return reinterpret_cast<jlong>(pResult);
}

extern "C"
JNIEXPORT jstring JNICALL
Java_com_web3auth_tss_1client_1android_dkls_SignatureFragments_jniSignatureFragmentsToString(
        JNIEnv *env, jobject thiz, jthrowable dkls_error) {
    int errorCode = 0;
    int *error_ptr = &errorCode;
    jlong pObject = GetPointerField(env, thiz);
    auto obj = reinterpret_cast<Sigfrags *>(pObject);
    const char* pResult = signature_fragments_to_string(obj, error_ptr);
    setErrorCode(env, dkls_error, errorCode);
    jstring result = env->NewStringUTF(pResult);
    dkls_string_free(const_cast<char*>(pResult));
    return result;
}

extern "C"
JNIEXPORT void JNICALL
Java_com_web3auth_tss_1client_1android_dkls_SignatureFragments_jniSignatureFragmentsFree(
        JNIEnv *env, jobject thiz) {
    jlong pObject = GetPointerField(env, thiz);
    auto pObj = reinterpret_cast<Sigfrags *>(pObject);
    signature_fragments_free(pObj);
}