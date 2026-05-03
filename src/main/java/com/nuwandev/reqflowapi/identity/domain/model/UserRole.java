package com.nuwandev.reqflowapi.identity.domain.model;

public enum UserRole {
    /**
     * create and view own requests; external comments; view own request attachments.
     */
    REQUESTOR,

    /**
     * view all requests (within tenant); update status; assign; internal comments.
     */
    AGENT,

    /**
     * view all requests; override assignments; access reports.
     */
    MANAGER,

    /**
     * manage users/teams/categories/SLAs; full audit access.
     */
    ADMIN,
}

