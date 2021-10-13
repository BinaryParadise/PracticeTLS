//
//  CanaryLog.swift
//  
//
//  Created by Rake Yang on 2021/6/24.
//

import Foundation
import Rainbow

public struct LogFlag: OptionSet {
    public let rawValue: Int

    public static let error   = LogFlag(rawValue: 1 << 0)
    public static let warning = LogFlag(rawValue: 1 << 1)
    public static let debug   = LogFlag(rawValue: 1 << 2)
    public static let info    = LogFlag(rawValue: 1 << 3)
    public static let verbose = LogFlag(rawValue: 1 << 4)
    
    public init(rawValue: Int) {
        self.rawValue = rawValue
    }

    public static let all: LogFlag = [.error, .warning, .info, .debug, .verbose]
}

public var dynamicLogLevel: LogFlag = .all

@inlinable
public func LogError(_ message: @autoclosure () -> String,
                       level: LogFlag = .error,
                       file: StaticString = #file,
                       function: StaticString = #function,
                       line: UInt = #line) {
    LogMessage(message(), level: level, file: file, function: function, line: line)
}

@inlinable
public func LogWarn(_ message: @autoclosure () -> String,
                       level: LogFlag = .warning,
                       file: StaticString = #file,
                       function: StaticString = #function,
                       line: UInt = #line) {
    LogMessage(message(), level: level, file: file, function: function, line: line)
}

@inlinable
public func LogDebug(_ message: @autoclosure () -> String,
                       level: LogFlag = .debug,
                       file: StaticString = #file,
                       function: StaticString = #function,
                       line: UInt = #line) {
    LogMessage(message(), level: level, file: file, function: function, line: line)
}

@inlinable
public func LogInfo(_ message: @autoclosure () -> String,
                       level: LogFlag = .info,
                       file: StaticString = #file,
                       function: StaticString = #function,
                       line: UInt = #line) {
    LogMessage(message(), level: level, file: file, function: function, line: line)
}

@inlinable
public func LogVerbose(_ message: @autoclosure () -> String,
                       level: LogFlag = .verbose,
                       file: StaticString = #file,
                       function: StaticString = #function,
                       line: UInt = #line) {
    LogMessage(message(), level: level, file: file, function: function, line: line)
}


@inlinable
public func LogMessage(_ message: @autoclosure () -> String,
                        level: LogFlag,
                        file: StaticString = #file,
                        function: StaticString = #function,
                        line: UInt = #line) {
    if dynamicLogLevel.contains(level) {
        let fmt = DateFormatter()
        fmt.dateFormat = "yyyy-MM-dd HH:mm:ss.SSS"
        let fname = URL(string: String(describing: file))?.lastPathComponent.deletingFileExtension ?? ""
        let log = "\(fmt.string(from: Date())) \(fname).\(function)+\(line) \(message())"
        if level == .error {
            print(log.red)
        } else if level == .warning {
            print(log.yellow)
        } else if level == .debug {
            print(log.cyan)
        } else if level == .info {
            print(log.white)
        } else {
            print(log.hex(0x666))
        }
    }
}
