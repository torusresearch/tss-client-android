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
    // TODO: implement jniCounterparties_From_String()
}

extern "C"
JNIEXPORT jbyteArray JNICALL
Java_com_web3auth_tss_1client_1android_dkls_Counterparties_jniCounterparties_1To_1String(
        JNIEnv *env, jobject thiz, jlong pointer, jthrowable error) {
    // TODO: implement jniCounterparties_To_String()
}

extern "C"
JNIEXPORT void JNICALL
Java_com_web3auth_tss_1client_1android_dkls_Counterparties_jniDkls_1string_1free(JNIEnv *env,
                                                                                 jobject thiz,
                                                                                 jbyteArray result) {
    // TODO: implement jniDkls_string_free()
}


extern "C"
JNIEXPORT void JNICALL
Java_com_web3auth_tss_1client_1android_dkls_Counterparties_jniCounterpartiesFree(JNIEnv *env,
                                                                                 jobject thiz,
                                                                                 jlong pointer) {
    jlong pObject = GetPointerField(env, thiz);
    auto pGenerator = reinterpret_cast<Counterparties *>(pObject);
    counterparties_free(pGenerator);
}