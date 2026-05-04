package com.nuwandev.reqflowapi.shared.response;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.core.MethodParameter;
import org.springframework.http.MediaType;
import org.springframework.http.server.ServerHttpRequest;
import org.springframework.http.server.ServerHttpResponse;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;
import org.springframework.web.servlet.mvc.method.annotation.ResponseBodyAdvice;

import java.time.Instant;
import java.time.format.DateTimeFormatter;
import java.util.UUID;

@ControllerAdvice
public class ApiResponseAdvice implements ResponseBodyAdvice<Object> {

    @Override
    public boolean supports(MethodParameter returnType, Class converterType) {
        return true;
    }

    @Override
    public Object beforeBodyWrite(Object body, MethodParameter returnType, MediaType selectedContentType,
                                  Class selectedConverterType, ServerHttpRequest request, ServerHttpResponse response) {
        if (body == null) {
            return null;
        }

        if (body instanceof SuccessEnvelope) {
            return body;
        }

        if (body instanceof ErrorEnvelope) {
            return body;
        }

        String traceId = getTraceId();
        String timestamp = DateTimeFormatter.ISO_INSTANT.format(Instant.now());
        return new SuccessEnvelope<>(body, new Meta(traceId, timestamp));
    }

    private String getTraceId() {
        ServletRequestAttributes attrs = (ServletRequestAttributes) RequestContextHolder.getRequestAttributes();
        if (attrs != null) {
            HttpServletRequest req = attrs.getRequest();
            Object attr = req.getAttribute(TraceIdFilter.TRACE_ID_REQUEST_ATTR);
            if (attr instanceof String s && !s.isBlank()) {
                return s;
            }

            String header = req.getHeader(TraceIdFilter.TRACE_ID_HEADER);
            if (header != null && !header.isBlank()) {
                return header;
            }
        }
        return UUID.randomUUID().toString();
    }
}
