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
Java_com_web3auth_tss_1client_1android_dkls_ChaChaRng_jniChaChaRng(JNIEnv *env,
                                                                   __attribute__((unused)) jobject thiz,
                                                                   jstring state,
                                                                   jthrowable error) {
    int errorCode = 0;
    int *error_ptr = &errorCode;
    const char *pState = env->GetStringUTFChars(state, JNI_FALSE);
    auto *pResult = random_generator(pState, error_ptr);
    env->ReleaseStringUTFChars(state, pState);
    setErrorCode(env, error, errorCode);
    return reinterpret_cast<jlong>(pResult);
}

extern "C"
JNIEXPORT void JNICALL
Java_com_web3auth_tss_1client_1android_dkls_ChaChaRng_jniChaChaRngFree(JNIEnv *env, jobject thiz) {
    jlong pObject = GetPointerField(env, thiz);
    auto pGenerator = reinterpret_cast<ChaChaRng *>(pObject);
    random_generator_free(pGenerator);
}