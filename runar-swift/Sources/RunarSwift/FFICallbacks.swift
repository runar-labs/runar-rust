import Foundation

// MARK: - Global Callback Storage (Start / Request)

private let startQueue = DispatchQueue(label: "runar.start.queue")
private var startCompletions: [ (Result<Void, RunarError>) -> Void ] = []

private let requestQueue = DispatchQueue(label: "runar.request.queue")
private var requestCompletions: [ (Result<String, RunarError>) -> Void ] = []

// Helper push functions used by Swift API
internal func pushStartCallback(_ cb: @escaping (Result<Void, RunarError>) -> Void) {
    startQueue.sync { startCompletions.append(cb) }
}

internal func pushRequestCallback(_ cb: @escaping (Result<String, RunarError>) -> Void) {
    requestQueue.sync { requestCompletions.append(cb) }
}

// Pop helpers (file-private)
private func popStartCallback() -> ((Result<Void, RunarError>) -> Void)? {
    return startQueue.sync {
        guard !startCompletions.isEmpty else { return nil }
        return startCompletions.removeFirst()
    }
}

private func popRequestCallback() -> ((Result<String, RunarError>) -> Void)? {
    return requestQueue.sync {
        guard !requestCompletions.isEmpty else { return nil }
        return requestCompletions.removeFirst()
    }
}

// MARK: - Global callback functions (no @_cdecl to avoid duplicate symbols)

public func swift_runar_start_callback_impl(_ ok: UnsafePointer<Int8>?, _ err: UnsafePointer<Int8>?) {
    guard let cb = popStartCallback() else { return }
    if let err = err {
        let errorStr = String(cString: err)
        cb(.failure(RunarError.unknownError(errorStr)))
    } else {
        cb(.success(()))
    }
}

public func swift_runar_request_callback_impl(_ data: UnsafePointer<Int8>, _ len: UInt, _ err: UnsafePointer<Int8>?) {
    guard let cb = popRequestCallback() else { return }
    if let err = err {
        let errorStr = String(cString: err)
        cb(.failure(RunarError.unknownError(errorStr)))
    } else {
        let resultStr = String(cString: data)
        cb(.success(resultStr))
    }
} 