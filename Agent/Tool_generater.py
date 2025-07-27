from typing import Annotated, Sequence, TypedDict
from dotenv import load_dotenv  
from langchain_core.messages import BaseMessage, ToolMessage, SystemMessage, AIMessage
from langchain_openai import ChatOpenAI
from langchain_core.tools import tool
from langgraph.graph.message import add_messages
from langgraph.graph import StateGraph, END
from langgraph.prebuilt import ToolNode
import ast

load_dotenv()

class AgentState(TypedDict):
    messages: Annotated[Sequence[BaseMessage], add_messages]

@tool
def add(a: int, b:int):
    """This is an addition function that adds 2 numbers together"""
    return a + b 

@tool
def subtract(a: int, b: int):
    """Subtraction function"""
    return a - b

@tool
def multiply(a: int, b: int):
    """Multiplication function"""
    return a * b

tools = [add, subtract, multiply]
model = ChatOpenAI(model="gpt-4o").bind_tools(tools)

def model_call(state: AgentState) -> AgentState:
    system_prompt = SystemMessage(content="You are my AI assistant. Answer the user or create tools if needed.")
    response = model.invoke([system_prompt] + state["messages"])
    return {"messages": [response]}

def generate_tool(state: AgentState) -> AgentState:
    last_msg = state["messages"][-1]
    if isinstance(last_msg, AIMessage):
        tool_prompt = "Write a Python @tool function to do the following:\n" + last_msg.content
        tool_response = model.invoke([
            #SystemMessage(content="You are a Python programmer. Only return valid and secure @tool function code. No backtriks no small talks"),
            system_message = SystemMessage(content="""
            You are a Python programmer. Only return valid and secure @tool function code. Your response must include only clean Python code — no markdown, no backticks, and no explanations.

            Rules and Security Constraints:

            1. The function must use the @tool decorator from langchain_core.tools.
            2. Never use or suggest the use of:
            - eval, exec
            - os.system, subprocess, Popen, shell=True
            - open, write, delete, or modify files
            - pip install, __import__, importlib
            - access to environment variables (os.environ)
            - any dynamic or arbitrary code execution

            3. Do not suggest installing packages or libraries.
            4. Do not import unsafe or obscure libraries — only use safe standard libraries or trusted APIs already imported.
            5. If the function interacts with external data (e.g., HTTP), it must:
            - use timeouts
            - limit the domain to trusted sources
            - validate and sanitize input parameters

            6. No infinite loops, deep recursion, or unbounded memory or CPU usage.
            7. Catch all exceptions gracefully and return safe, user-readable error messages.
            8. Do not include credentials, API keys, tokens, or instructions to include them.
            9. Never expose stack traces or internal logs.
            10. Do not suggest modifying system state or accessing privileged information.

            Your only output must be clean, safe, minimal Python function code decorated with @tool.
            """)
            AIMessage(content=tool_prompt)
        ])
        code = tool_response.content
        local_vars = {}
        try:
            exec(code, {"tool": tool}, local_vars)
            new_tool = list(local_vars.values())[0]
            tools.append(new_tool)
            global model
            model = ChatOpenAI(model="gpt-4o").bind_tools(tools)
            return {"messages": [AIMessage(content="Tool created successfully.")]}
        except Exception as e:
            return {"messages": [AIMessage(content=f"Tool creation failed: {str(e)}")]}
    return {"messages": [AIMessage(content="No tool needed.")]}

def should_continue(state: AgentState): 
    messages = state["messages"]
    last_message = messages[-1]
    if hasattr(last_message, "tool_calls") and last_message.tool_calls:
        return "continue"
    elif isinstance(last_message, AIMessage) and "create a tool" in last_message.content.lower():
        return "generate_tool"
    else:
        return "end"

graph = StateGraph(AgentState)
graph.add_node("our_agent", model_call)
tool_node = ToolNode(tools=tools)
graph.add_node("tools", tool_node)
graph.add_node("generate_tool", generate_tool)
graph.set_entry_point("our_agent")

graph.add_conditional_edges(
    "our_agent",
    should_continue,
    {
        "continue": "tools",
        "generate_tool": "generate_tool",
        "end": END,
    },
)

graph.add_edge("tools", "our_agent")
graph.add_edge("generate_tool", "our_agent")
app = graph.compile()

def print_stream(stream):
    for s in stream:
        message = s["messages"][-1]
        if isinstance(message, tuple):
            print(message)
        else:
            message.pretty_print()

inputs = {"messages": [("user", "Create a tool that calculates the square root of a number and then use it on 144.")]}
print_stream(app.stream(inputs, stream_mode="values"))
