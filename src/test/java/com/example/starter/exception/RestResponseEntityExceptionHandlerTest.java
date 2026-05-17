package com.example.starter.exception;

import jakarta.validation.ConstraintViolation;
import jakarta.validation.ConstraintViolationException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpStatus;
import org.springframework.http.ProblemDetail;
import org.springframework.http.ResponseEntity;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.test.util.ReflectionTestUtils;
import org.springframework.web.context.request.ServletWebRequest;
import org.springframework.web.context.request.WebRequest;

import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class RestResponseEntityExceptionHandlerTest {

    private RestResponseEntityExceptionHandler handler;

    @BeforeEach
    void setUp() {
        handler = new RestResponseEntityExceptionHandler();
        ReflectionTestUtils.setField(handler, "urn", "starter");
    }

    @Test
    void handleAccessDeniedExceptionReturnsUnauthorizedProblemDetail() {
        WebRequest request = new ServletWebRequest(new MockHttpServletRequest());
        AccessDeniedException exception = new AccessDeniedException("access denied");

        ResponseEntity<Object> response = handler.handleAccessDeniedException(exception, request);

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
        ProblemDetail body = (ProblemDetail) response.getBody();
        assertThat(body).isNotNull();
        assertThat(body.getDetail()).contains("No access the desired resource");
        assertThat(body.getTitle()).isEqualTo("access denied");
        assertThat(body.getType()).isNotNull();
        assertThat(body.getType().toString()).isEqualTo("urn:starter");
    }

    @Test
    void handleConstraintViolatedExceptionReturnsBadRequestWithJoinedMessages() {
        ConstraintViolation<?> first = mock(ConstraintViolation.class);
        ConstraintViolation<?> second = mock(ConstraintViolation.class);
        when(first.getMessage()).thenReturn("username required");
        when(second.getMessage()).thenReturn("email invalid");

        ConstraintViolationException exception =
            new ConstraintViolationException("validation failed", Set.of(first, second));
        WebRequest request = new ServletWebRequest(new MockHttpServletRequest());

        ResponseEntity<Object> response = handler.handleConstraintViolatedException(exception, request);

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.BAD_REQUEST);
        ProblemDetail body = (ProblemDetail) response.getBody();
        assertThat(body).isNotNull();
        assertThat(body.getDetail()).contains("username required");
        assertThat(body.getDetail()).contains("email invalid");
        assertThat(body.getType()).isNotNull();
        assertThat(body.getType().toString()).isEqualTo("urn:starter");
    }

    @Test
    void handleResourceAlreadyExistsReturnsConflict() {
        ResourceAlreadyExistsException exception = new ResourceAlreadyExistsException("user already exists");
        WebRequest request = new ServletWebRequest(new MockHttpServletRequest());

        ResponseEntity<Object> response = handler.handleResourceAlreadyExists(exception, request);

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.CONFLICT);
        ProblemDetail body = (ProblemDetail) response.getBody();
        assertThat(body).isNotNull();
        assertThat(body.getDetail()).isEqualTo("Conflict: user already exists");
        assertThat(body.getTitle()).isEqualTo("user already exists");
    }

    @Test
    void handleResourceNotFoundReturnsNotFound() {
        ResourceNotFoundException exception = new ResourceNotFoundException("user not found");
        WebRequest request = new ServletWebRequest(new MockHttpServletRequest());

        ResponseEntity<Object> response = handler.handleResourceNotFound(exception, request);

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.NOT_FOUND);
        ProblemDetail body = (ProblemDetail) response.getBody();
        assertThat(body).isNotNull();
        assertThat(body.getDetail()).isEqualTo("Resource Not Found: user not found");
        assertThat(body.getTitle()).isEqualTo("user not found");
    }
}

