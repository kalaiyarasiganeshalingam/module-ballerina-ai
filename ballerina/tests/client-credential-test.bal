// Copyright (c) 2026 WSO2 LLC (http://www.wso2.com).
//
// WSO2 LLC. licenses this file to you under the Apache License,
// Version 2.0 (the "License"); you may not use this file except
// in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing,
// software distributed under the License is distributed on an
// "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.  See the License for the
// specific language governing permissions and limitations
// under the License.

import ballerina/http;
import ballerina/jballerina.java;
import ballerina/test;

// ─── Constants ────────────────────────────────────────────────────────────────

const int MOCK_TOKEN_PORT = 9099;
const string MOCK_TOKEN_URL = "http://localhost:9099/oauth2/token";
const string MOCK_CLIENT_ID = "agent-client-001";
const string MOCK_CLIENT_SECRET = "super-secret-key";
const string MOCK_ACCESS_TOKEN = "tok-abc123xyz";
const string WEATHER_SCOPE = "read_weather";
const string ORDERS_SCOPE = "read_orders";
const string WEATHER_SERVICE_URL = "https://weather.example.com";

// ─── Shared test state (single isolated record) ───────────────────────────────

isolated record {|
    string grantType;
    string clientId;
    string scope;
    string serviceUrl;
    string authHeader;
    string clientSecretBody;
    int callCount;
    string toolReceivedToken;
    string mockResponseScope;
|} testState = {
    grantType: "",
    clientId: "",
    scope: "",
    serviceUrl: "",
    authHeader: "",
    clientSecretBody: "",
    callCount: 0,
    toolReceivedToken: "",
    mockResponseScope: ""
};

// ─── Mock OAuth2 token endpoint ───────────────────────────────────────────────

service on new http:Listener(MOCK_TOKEN_PORT) {

    resource function post oauth2/token(http:Request req) returns json|error {
        map<string> params = check req.getFormParams();
        string authHeader = "";
        string|error authResult = req.getHeader("Authorization");
        if authResult is string {
            authHeader = authResult;
        }

        string responseScope;
        lock {
            testState.grantType = params["grant_type"] ?: "";
            testState.clientId = params["client_id"] ?: "";
            testState.scope = params["scope"] ?: "";
            testState.serviceUrl = params["resource"] ?: "";
            testState.authHeader = authHeader;
            testState.clientSecretBody = params["client_secret"] ?: "";
            testState.callCount += 1;
            responseScope = testState.mockResponseScope == ""
                ? (params["scope"] ?: "") : testState.mockResponseScope;
        }

        return {
            access_token: MOCK_ACCESS_TOKEN,
            token_type: "Bearer",
            expires_in: 3600,
            scope: responseScope
        };
    }
}

// ─── Mock LLMs ────────────────────────────────────────────────────────────────

public isolated client class WeatherToolMockLLM {
    *ModelProvider;
    private int callCount = 0;

    isolated remote function chat(ChatMessage[]|ChatUserMessage messages,
            ChatCompletionFunctions[] tools = [], string? stop = ())
            returns ChatAssistantMessage|LlmError {
        lock {
            self.callCount += 1;
            if self.callCount == 1 {
                return {
                    role: ASSISTANT,
                    toolCalls: [{name: "getWeatherTool", arguments: {city: "London"}, id: "call-1"}]
                };
            }
        }
        return {role: ASSISTANT, content: "The weather in London is Sunny, 25°C."};
    }

    isolated remote function generate(Prompt prompt, typedesc<anydata> td = <>) returns td|Error =
        @java:Method {'class: "io.ballerina.lib.ai.MockGenerator"} external;
}

public isolated client class RepeatableWeatherMockLLM {
    *ModelProvider;
    private int callCount = 0;

    isolated remote function chat(ChatMessage[]|ChatUserMessage messages,
            ChatCompletionFunctions[] tools = [], string? stop = ())
            returns ChatAssistantMessage|LlmError {
        lock {
            self.callCount += 1;
            if self.callCount % 2 == 1 {
                return {
                    role: ASSISTANT,
                    toolCalls: [{name: "getWeatherTool", arguments: {city: "London"}, id: "call-1"}]
                };
            }
        }
        return {role: ASSISTANT, content: "Done."};
    }

    isolated remote function generate(Prompt prompt, typedesc<anydata> td = <>) returns td|Error =
        @java:Method {'class: "io.ballerina.lib.ai.MockGenerator"} external;
}

public isolated client class OrderToolMockLLM {
    *ModelProvider;
    private int callCount = 0;

    isolated remote function chat(ChatMessage[]|ChatUserMessage messages,
            ChatCompletionFunctions[] tools = [], string? stop = ())
            returns ChatAssistantMessage|LlmError {
        lock {
            self.callCount += 1;
            if self.callCount == 1 {
                return {
                    role: ASSISTANT,
                    toolCalls: [{name: "getOrderTool", arguments: {}, id: "call-2"}]
                };
            }
        }
        return {role: ASSISTANT, content: "Your orders: order-1, order-2."};
    }

    isolated remote function generate(Prompt prompt, typedesc<anydata> td = <>) returns td|Error =
        @java:Method {'class: "io.ballerina.lib.ai.MockGenerator"} external;
}

public isolated client class NoSvcUrlWeatherMockLLM {
    *ModelProvider;
    private int callCount = 0;

    isolated remote function chat(ChatMessage[]|ChatUserMessage messages,
            ChatCompletionFunctions[] tools = [], string? stop = ())
            returns ChatAssistantMessage|LlmError {
        lock {
            self.callCount += 1;
            if self.callCount == 1 {
                return {
                    role: ASSISTANT,
                    toolCalls: [{name: "getWeatherNoSvcUrl", arguments: {city: "Paris"}, id: "call-3"}]
                };
            }
        }
        return {role: ASSISTANT, content: "Weather fetched."};
    }

    isolated remote function generate(Prompt prompt, typedesc<anydata> td = <>) returns td|Error =
        @java:Method {'class: "io.ballerina.lib.ai.MockGenerator"} external;
}

// ─── Tool caller functions ────────────────────────────────────────────────────

isolated function getWeatherToolCaller(Context ctx, string city) returns string|error {
    string token = check ctx.getAccessToken("getWeatherTool");
    lock {
        testState.toolReceivedToken = token;
    }
    return string `Weather in ${city}: Sunny, 25°C`;
}

isolated function getOrderToolCaller(Context ctx) returns string|error {
    string token = check ctx.getAccessToken("getOrderTool");
    lock {
        testState.toolReceivedToken = token;
    }
    return "Orders: [order-1, order-2]";
}

isolated function getWeatherNoSvcUrlCaller(Context ctx, string city) returns string|error {
    _ = check ctx.getAccessToken("getWeatherNoSvcUrl");
    return string `Weather in ${city}: Cloudy`;
}

// ─── ToolConfig records ───────────────────────────────────────────────────────

ToolConfig weatherToolConfig = {
    name: "getWeatherTool",
    description: "Get the current weather for a given city.",
    parameters: {
        properties: {
            city: {'type: "string", description: "The name of the city"}
        }
    },
    caller: getWeatherToolCaller,
    requiredPermission: {
        scopes: [WEATHER_SCOPE],
        serviceUrl: WEATHER_SERVICE_URL
    }
};

ToolConfig orderToolConfig = {
    name: "getOrderTool",
    description: "Get the list of orders.",
    caller: getOrderToolCaller,
    requiredPermission: {}
};

ToolConfig weatherNoSvcUrlConfig = {
    name: "getWeatherNoSvcUrl",
    description: "Get the current weather for a given city (no service URL).",
    parameters: {
        properties: {
            city: {'type: "string", description: "The name of the city"}
        }
    },
    caller: getWeatherNoSvcUrlCaller,
    requiredPermission: {scopes: [WEATHER_SCOPE]}
};

// ─── Helper ───────────────────────────────────────────────────────────────────

isolated function resetState() {
    lock {
        testState.grantType = "";
        testState.clientId = "";
        testState.scope = "";
        testState.serviceUrl = "";
        testState.authHeader = "";
        testState.clientSecretBody = "";
        testState.callCount = 0;
        testState.toolReceivedToken = "";
        testState.mockResponseScope = "";
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

// 1. Token is acquired with grant_type=client_credentials and correct params.
//    The returned access token is made available to the tool via Context.
@test:Config {
    groups: ["client-credential"]
}
function testClientCredentialTokenAcquisition() returns error? {
    resetState();
    Agent agent = check new ({
        systemPrompt: {role: "Weather Agent", instructions: "Answer weather queries."},
        model: new WeatherToolMockLLM(),
        tools: [weatherToolConfig],
        auth: {
            tokenUrl: MOCK_TOKEN_URL,
            clientId: MOCK_CLIENT_ID,
            clientAuth: {secret: MOCK_CLIENT_SECRET}
        }
    });

    Trace _ = check agent.run("What is the weather in London?");

    lock {
        test:assertEquals(testState.callCount, 1, "Token endpoint should be called exactly once");
        test:assertEquals(testState.grantType, "client_credentials");
        test:assertEquals(testState.clientId, MOCK_CLIENT_ID);
        test:assertEquals(testState.scope, WEATHER_SCOPE);
        test:assertEquals(testState.toolReceivedToken, MOCK_ACCESS_TOKEN,
            "Tool must receive the access token via Context.getAccessToken()");
    }
}

// 2. client_secret_basic: secret is sent in Authorization: Basic header, not in body.
@test:Config {
    groups: ["client-credential"]
}
function testClientCredentialClientSecretBasicAuth() returns error? {
    resetState();
    Agent agent = check new ({
        systemPrompt: {role: "Weather Agent", instructions: "Answer weather queries."},
        model: new WeatherToolMockLLM(),
        tools: [weatherToolConfig],
        auth: {
            tokenUrl: MOCK_TOKEN_URL,
            clientId: MOCK_CLIENT_ID,
            clientAuth: {secret: MOCK_CLIENT_SECRET, method: BASIC}
        }
    });

    Trace _ = check agent.run("What is the weather in London?");

    lock {
        test:assertTrue(testState.authHeader.startsWith("Basic "),
            "Authorization header must use the Basic scheme for BASIC method");
        test:assertEquals(testState.clientSecretBody, "",
            "client_secret must NOT be in the request body for BASIC method");
    }
}

// 3. client_secret_post: secret is sent in the request body, no Authorization header.
@test:Config {
    groups: ["client-credential"]
}
function testClientCredentialClientSecretPostBody() returns error? {
    resetState();
    Agent agent = check new ({
        systemPrompt: {role: "Weather Agent", instructions: "Answer weather queries."},
        model: new WeatherToolMockLLM(),
        tools: [weatherToolConfig],
        auth: {
            tokenUrl: MOCK_TOKEN_URL,
            clientId: MOCK_CLIENT_ID,
            clientAuth: {secret: MOCK_CLIENT_SECRET, method: BODY}
        }
    });

    Trace _ = check agent.run("What is the weather in London?");

    lock {
        test:assertEquals(testState.clientSecretBody, MOCK_CLIENT_SECRET,
            "client_secret must be in the request body for BODY method");
        test:assertEquals(testState.authHeader, "",
            "No Authorization header must be set for BODY method");
    }
}

// 4. Tool-level serviceUrl is sent as the `resource` parameter (RFC 8707).
@test:Config {
    groups: ["client-credential"]
}
function testClientCredentialServiceUrlSentAsResource() returns error? {
    resetState();
    Agent agent = check new ({
        systemPrompt: {role: "Weather Agent", instructions: "Answer weather queries."},
        model: new WeatherToolMockLLM(),
        tools: [weatherToolConfig],
        auth: {
            tokenUrl: MOCK_TOKEN_URL,
            clientId: MOCK_CLIENT_ID,
            clientAuth: {secret: MOCK_CLIENT_SECRET}
        }
    });

    Trace _ = check agent.run("What is the weather in London?");

    lock {
        test:assertEquals(testState.serviceUrl, WEATHER_SERVICE_URL,
            "Tool serviceUrl must be sent as the 'resource' parameter (RFC 8707)");
    }
}

// 5. Tool-level serviceUrl overrides any resource set in agent-level optionalParams.
@test:Config {
    groups: ["client-credential"]
}
function testClientCredentialServiceUrlOverridesOptionalParams() returns error? {
    resetState();
    Agent agent = check new ({
        systemPrompt: {role: "Weather Agent", instructions: "Answer weather queries."},
        model: new WeatherToolMockLLM(),
        tools: [weatherToolConfig],
        auth: {
            tokenUrl: MOCK_TOKEN_URL,
            clientId: MOCK_CLIENT_ID,
            clientAuth: {secret: MOCK_CLIENT_SECRET},
            optionalParams: {"resource": "https://default-api.example.com"}
        }
    });

    Trace _ = check agent.run("What is the weather in London?");

    lock {
        test:assertEquals(testState.serviceUrl, WEATHER_SERVICE_URL,
            "Tool-level serviceUrl must override agent-level optionalParams resource");
    }
}

// 6. When a tool's requiredPermission declares no scopes, the agent-level scopes
//    are merged (in this case, only agent scopes are used since tool scopes are empty).
@test:Config {
    groups: ["client-credential"]
}
function testClientCredentialAgentScopesFallback() returns error? {
    resetState();
    Agent agent = check new ({
        systemPrompt: {role: "Order Agent", instructions: "Answer order queries."},
        model: new OrderToolMockLLM(),
        tools: [orderToolConfig],
        auth: {
            tokenUrl: MOCK_TOKEN_URL,
            clientId: MOCK_CLIENT_ID,
            clientAuth: {secret: MOCK_CLIENT_SECRET},
            scopes: [ORDERS_SCOPE]
        }
    });

    Trace _ = check agent.run("Show me my orders.");

    lock {
        test:assertEquals(testState.scope, ORDERS_SCOPE,
            "Agent-level scopes must be used when tool requiredPermission declares no scopes");
        test:assertEquals(testState.toolReceivedToken, MOCK_ACCESS_TOKEN);
    }
}

// 7. A second agent.run() reuses the cached token — the token endpoint is called
//    only once across two runs of the same agent instance.
@test:Config {
    groups: ["client-credential"]
}
function testClientCredentialTokenIsCached() returns error? {
    resetState();
    Agent agent = check new ({
        systemPrompt: {role: "Weather Agent", instructions: "Answer weather queries."},
        model: new RepeatableWeatherMockLLM(),
        tools: [weatherToolConfig],
        auth: {
            tokenUrl: MOCK_TOKEN_URL,
            clientId: MOCK_CLIENT_ID,
            clientAuth: {secret: MOCK_CLIENT_SECRET}
        }
    });

    Trace _ = check agent.run("What is the weather in London?");
    Trace _ = check agent.run("What is the weather in London again?");

    lock {
        test:assertEquals(testState.callCount, 1,
            "Token endpoint must be called only once; the second run must reuse the cached token");
    }
}

// 8. When the server returns fewer scopes than the tool requires, an InsufficientScopeError
//    is raised and the tool is NOT invoked.
@test:Config {
    groups: ["client-credential"]
}
function testClientCredentialInsufficientScope() returns error? {
    resetState();
    lock {
        testState.mockResponseScope = "read_only";
    }
    Agent agent = check new ({
        systemPrompt: {role: "Weather Agent", instructions: "Answer weather queries."},
        model: new WeatherToolMockLLM(),
        tools: [weatherToolConfig],
        auth: {
            tokenUrl: MOCK_TOKEN_URL,
            clientId: MOCK_CLIENT_ID,
            clientAuth: {secret: MOCK_CLIENT_SECRET}
        }
    });

    // The agent treats InsufficientScopeError as a failed tool observation and continues.
    // agent.run() returns a Trace rather than propagating the error.
    Trace _ = check agent.run("What is the weather in London?");

    lock {
        test:assertEquals(testState.callCount, 1,
            "Token endpoint must be called once (scope checked before tool invocation)");
        test:assertEquals(testState.toolReceivedToken, "",
            "Tool must not be invoked when the returned scopes are insufficient");
    }
}

// 9. Agent-level optionalParams are forwarded in the token request when no tool
//    serviceUrl is set.
@test:Config {
    groups: ["client-credential"]
}
function testClientCredentialOptionalParamsForwarded() returns error? {
    resetState();
    Agent agent = check new ({
        systemPrompt: {role: "Weather Agent", instructions: "Answer weather queries."},
        model: new NoSvcUrlWeatherMockLLM(),
        tools: [weatherNoSvcUrlConfig],
        auth: {
            tokenUrl: MOCK_TOKEN_URL,
            clientId: MOCK_CLIENT_ID,
            clientAuth: {secret: MOCK_CLIENT_SECRET},
            optionalParams: {"resource": "https://api.example.com"}
        }
    });

    Trace _ = check agent.run("Weather in Paris?");

    lock {
        test:assertEquals(testState.serviceUrl, "https://api.example.com",
            "optionalParams resource must be forwarded when no tool serviceUrl is set");
    }
}
