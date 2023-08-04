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
Java_com_web3auth_tss_1client_1android_dkls_Counterparties_jniCounterparties_1From_1String(
        JNIEnv *env, jobject thiz, jstring parties, jthrowable error) {
    int errorCode = 0;
    int *error_ptr = &errorCode;
    const char *pParties = env->GetStringUTFChars(parties, JNI_FALSE);
    auto *pResult = counterparties_from_string(pParties, error_ptr);
    env->ReleaseStringUTFChars(parties, pParties);
    setErrorCode(env, error, errorCode);
    return reinterpret_cast<jlong>(pResult);
}

extern "C"
JNIEXPORT jstring JNICALL
Java_com_web3auth_tss_1client_1android_dkls_Counterparties_jniCounterparties_1To_1String(
        JNIEnv *env, jobject thiz, jthrowable error) {
    int errorCode = 0;
    int *error_ptr = &errorCode;
    jlong pObject = GetPointerField(env, thiz);
    auto obj = reinterpret_cast<Counterparties *>(pObject);
    const char* pResult = (counterparties_to_string(obj, error_ptr));
    setErrorCode(env, error, errorCode);
    jstring result = env->NewStringUTF(pResult);
    dkls_string_free(const_cast<char*>(pResult));
    return result;
}

extern "C"
JNIEXPORT void JNICALL
Java_com_web3auth_tss_1client_1android_dkls_Counterparties_jniCounterpartiesFree(JNIEnv *env, jobject thiz) {
    jlong pObject = GetPointerField(env, thiz);
    auto obj = reinterpret_cast<Counterparties *>(pObject);
    counterparties_free(obj);
}