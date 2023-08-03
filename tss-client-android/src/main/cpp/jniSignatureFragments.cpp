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
        JNIEnv *env, jobject thiz, jbyteArray input, jthrowable dkls_error) {
    // TODO: implement jniSignatureFragmentsFromString()
}

extern "C"
JNIEXPORT jbyteArray JNICALL
Java_com_web3auth_tss_1client_1android_dkls_SignatureFragments_jniSignatureFragmentsToString(
        JNIEnv *env, jobject thiz, jlong ptr, jthrowable dkls_error) {
    // TODO: implement jniSignatureFragmentsToString()
}

extern "C"
JNIEXPORT void JNICALL
Java_com_web3auth_tss_1client_1android_dkls_SignatureFragments_jniDklsStringFree(JNIEnv *env,
                                                                                 jobject thiz,
                                                                                 jbyteArray result) {
    // TODO: implement jniDklsStringFree()
}

extern "C"
JNIEXPORT void JNICALL
Java_com_web3auth_tss_1client_1android_dkls_SignatureFragments_jniSignatureFragmentsFree(
        JNIEnv *env, jobject thiz) {
    jlong pObject = GetPointerField(env, thiz);
    auto pGenerator = reinterpret_cast<Sigfrags *>(pObject);
    signature_fragments_free(pGenerator);
}