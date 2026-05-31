// Narrows an unknown throw to an object carrying a numeric statusCode.
function isHttpError(err: unknown): err is { statusCode: number } {
    return typeof err === 'object' && err !== null && 'statusCode' in err && typeof (err as any).statusCode === 'number'
}

/**
 * Returns true if the error is a 403 Forbidden from the Kubernetes API.
 * @param err Error thrown by a k8s API call.
 */
export function isForbidden(err: unknown): boolean {
    return isHttpError(err) && err.statusCode === 403
}

/**
 * Returns true if the error is a 409 Conflict, indicating the resource already exists.
 * @param err Error thrown by a k8s API call.
 */
export function isConflict(err: unknown): boolean {
    return isHttpError(err) && err.statusCode === 409
}

/**
 * Returns true if the error is a 401 Unauthorized from the Kubernetes API.
 * @param err Error thrown by a k8s API call.
 */
export function isUnauthorized(err: unknown): boolean {
    return isHttpError(err) && err.statusCode === 401
}

/**
 * Returns true if the error is a 404 Not Found from the Kubernetes API.
 * @param err Error thrown by a k8s API call.
 */
export function isNotFound(err: unknown): boolean {
    return isHttpError(err) && err.statusCode === 404
}
