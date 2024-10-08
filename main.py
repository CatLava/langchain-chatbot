#!/usr/bin/env python3
import os
from dotenv import load_dotenv
from langchain_core.language_models import BaseLanguageModel
from langchain_core.messages import (
    HumanMessage,
)
from langgraph.prebuilt import ToolNode
from langgraph.graph import END, START, StateGraph, MessagesState
from typing import Annotated, Literal

from langgraph.checkpoint.memory import MemorySaver
from langchain_anthropic import ChatAnthropic
from aws_tools import (
    get_aws_account_info,
    list_aws_s3_buckets,
    list_aws_iam_users,
    get_aws_iam_user_permissions,
    is_aws_s3_bucket_public,
    list_aws_s3_bucket_objects,
    get_ec2_instances
)


load_dotenv()

ANTHROPIC_TOKEN = os.getenv("ANTRHOPIC_API_KEY")

tools = [
    get_aws_account_info,
    list_aws_s3_buckets,
    list_aws_iam_users,
    get_aws_iam_user_permissions,
    is_aws_s3_bucket_public,
    list_aws_s3_bucket_objects,
    get_ec2_instances
]

tool_node = ToolNode(tools)


model = ChatAnthropic(
    model="claude-3-5-sonnet-20240620", temperature=0, api_key=ANTHROPIC_TOKEN
).bind_tools(tools)


# Define the function that determines whether to continue or not
def should_continue(state: MessagesState) -> Literal["tools", END]:
    messages = state["messages"]
    last_message = messages[-1]
    # If the LLM makes a tool call, then we route to the "tools" node
    if last_message.tool_calls:
        return "tools"
    # Otherwise, we stop (reply to the user)
    return END


# Define the function that calls the model
def call_model(state: MessagesState):
    messages = state["messages"]
    response = model.invoke(messages)
    # We return a list, because this will get added to the existing list
    return {"messages": [response]}


# Define a new graph
workflow = StateGraph(MessagesState)

# Define the two nodes we will cycle between
workflow.add_node("agent", call_model)
workflow.add_node("tools", tool_node)

workflow.add_edge(START, "agent")

# We now add a conditional edge
workflow.add_conditional_edges(
    # First, we define the start node. We use `agent`.
    # This means these are the edges taken after the `agent` node is called.
    "agent",
    # Next, we pass in the function that will determine which node is called next.
    should_continue,
)

# We now add a normal edge from `tools` to `agent`.
# This means that after `tools` is called, `agent` node is called next.
workflow.add_edge("tools", "agent")

# Initialize memory to persist state between graph runs
checkpointer = MemorySaver()


if __name__ == "__main__":
    app = workflow.compile(checkpointer=checkpointer)
    print(
        "This is an AI chatbot focused on AWS content, please ensure your environment is correct"
    )
    while True:
        # # Ask the user for input and store it in a variable
        user_input = input("Ask a question related to your AWS environment: ")
        final_state = app.invoke(
            {"messages": [HumanMessage(content=user_input)]},
            config={"configurable": {"thread_id": 42}},
        )

        print(final_state["messages"][-1].content)
