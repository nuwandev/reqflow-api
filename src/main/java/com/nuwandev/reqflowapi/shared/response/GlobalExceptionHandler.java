package com.nuwandev.reqflowapi.shared.response;

import com.nuwandev.reqflowapi.auth.domain.exception.InactiveUserException;
import com.nuwandev.reqflowapi.auth.domain.exception.InvalidCredentialsException;
import com.nuwandev.reqflowapi.auth.domain.exception.InvalidRefreshTokenException;
import com.nuwandev.reqflowapi.auth.domain.exception.RefreshTokenReuseDetectedException;
import com.nuwandev.reqflowapi.shared.response.ErrorDetail;
import com.nuwandev.reqflowapi.shared.response.ErrorEnvelope;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.ConstraintViolationException;
import org.springframework.http.HttpStatus;
import org.springframework.validation.BindException;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

import java.time.Instant;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

@RestControllerAdvice
public class GlobalExceptionHandler {

    @ExceptionHandler({
            MethodArgumentNotValidException.class,
            BindException.class,
            ConstraintViolationException.class,
            IllegalArgumentException.class
    })
    @ResponseStatus(HttpStatus.BAD_REQUEST)
    public ErrorEnvelope handleBadRequest(Exception exception) {
        List<ErrorDetail> details = extractValidationDetails(exception);
        return createErrorEnvelope("VALIDATION_ERROR", "One or more fields are invalid", details);
    }

    @ExceptionHandler({
            InvalidCredentialsException.class,
            InvalidRefreshTokenException.class,
            RefreshTokenReuseDetectedException.class
    })
    @ResponseStatus(HttpStatus.UNAUTHORIZED)
    public ErrorEnvelope handleUnauthorized(RuntimeException exception) {
        return createErrorEnvelope("UNAUTHORIZED", "Unauthorized", null);
    }

    @ExceptionHandler(InactiveUserException.class)
    @ResponseStatus(HttpStatus.FORBIDDEN)
    public ErrorEnvelope handleForbidden(InactiveUserException exception) {
        return createErrorEnvelope("FORBIDDEN", "Forbidden", null);
    }

    private List<ErrorDetail> extractValidationDetails(Exception exception) {
        List<ErrorDetail> details = new ArrayList<>();
        if (exception instanceof MethodArgumentNotValidException manv) {
            manv.getBindingResult().getFieldErrors().forEach(err ->
                    details.add(new ErrorDetail(err.getField(), err.getDefaultMessage()))
            );
        } else if (exception instanceof BindException be) {
            be.getBindingResult().getFieldErrors().forEach(err ->
                    details.add(new ErrorDetail(err.getField(), err.getDefaultMessage()))
            );
        }
        return details.isEmpty() ? null : details;
    }

    private ErrorEnvelope createErrorEnvelope(String errorCode, String message, List<ErrorDetail> details) {
        String traceId = getTraceId();
        String timestamp = DateTimeFormatter.ISO_INSTANT.format(Instant.now());
        return new ErrorEnvelope(errorCode, message, details, traceId, timestamp);
    }

    private String getTraceId() {
        var attrs = (ServletRequestAttributes) RequestContextHolder.getRequestAttributes();
        if (attrs != null) {
            HttpServletRequest req = attrs.getRequest();
            Object attr = req.getAttribute(TraceIdFilter.TRACE_ID_REQUEST_ATTR);
            if (attr instanceof String s && !s.isBlank()) return s;
            String header = req.getHeader(TraceIdFilter.TRACE_ID_HEADER);
            if (header != null && !header.isBlank()) return header;
        }
        return UUID.randomUUID().toString();
    }
}

