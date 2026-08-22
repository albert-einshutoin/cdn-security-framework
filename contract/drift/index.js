"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.compareRequestContracts = exports.comparePathMethodContracts = exports.compareAuthContracts = void 0;
exports.compareSecurityContracts = compareSecurityContracts;
const authentication_1 = require("./authentication");
const path_method_1 = require("./path-method");
const request_1 = require("./request");
const shared_1 = require("./shared");
var authentication_2 = require("./authentication");
Object.defineProperty(exports, "compareAuthContracts", { enumerable: true, get: function () { return authentication_2.compareAuthContracts; } });
var path_method_2 = require("./path-method");
Object.defineProperty(exports, "comparePathMethodContracts", { enumerable: true, get: function () { return path_method_2.comparePathMethodContracts; } });
var request_2 = require("./request");
Object.defineProperty(exports, "compareRequestContracts", { enumerable: true, get: function () { return request_2.compareRequestContracts; } });
function compareSecurityContracts(input, options = {}) {
    return (0, shared_1.stableFindings)([
        ...(0, path_method_1.comparePathMethodContracts)(input),
        ...(0, authentication_1.compareAuthContracts)(input),
        ...(0, request_1.compareRequestContracts)(input, options),
    ]);
}
