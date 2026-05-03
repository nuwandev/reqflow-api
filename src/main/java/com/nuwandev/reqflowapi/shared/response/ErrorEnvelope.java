package com.nuwandev.reqflowapi.shared.response;

import java.util.List;

public record ErrorEnvelope(
        String errorCode,
        String message,
        List<ErrorDetail> details,
        String traceId,
        String timestamp
) {
}

