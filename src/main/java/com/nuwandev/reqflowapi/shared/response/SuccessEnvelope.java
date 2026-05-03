package com.nuwandev.reqflowapi.shared.response;

public record SuccessEnvelope<T>(T data, Meta meta) {
}


