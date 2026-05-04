"""
A typical LangChain agent - works great, but has zero compliance coverage.

This is how most developers build LangChain apps today.
No logging. No input validation. No audit trail. No human oversight.

Run the AIR Blackbox scanner to see what's missing:
    air-blackbox comply --scan ./demo/langchain-before-after/ --verbose
"""

from langchain_openai import ChatOpenAI
from langchain_core.prompts import ChatPromptTemplate
from langchain_core.output_parsers import StrOutputParser
from langchain.agents import create_tool_calling_agent, AgentExecutor
from langchain_core.tools import tool


# --- Tools ---

@tool
def search_database(query: str) -> str:
    """Search the company database for information."""
    # Simulated database search - no input sanitization
    return f"Results for '{query}': Found 3 matching records."


@tool
def send_email(to: str, subject: str, body: str) -> str:
    """Send an email to a customer."""
    # No approval gate - agent can email anyone automatically
    return f"Email sent to {to}: {subject}"


@tool
def update_record(record_id: str, new_value: str) -> str:
    """Update a database record."""
    # No permission check, no audit log
    return f"Record {record_id} updated to: {new_value}"


# --- Agent setup ---

llm = ChatOpenAI(model="gpt-4o-mini")

prompt = ChatPromptTemplate.from_messages([
    ("system", "You are a helpful customer service agent. Help users with their requests."),
    ("human", "{input}"),  # Raw user input - no sanitization
    ("placeholder", "{agent_scratchpad}"),
])

tools = [search_database, send_email, update_record]
agent = create_tool_calling_agent(llm, tools, prompt)
executor = AgentExecutor(agent=agent, tools=tools)


# --- Run ---

if __name__ == "__main__":
    # User input goes straight to the LLM - no validation, no PII check
    user_input = input("What can I help you with? > ")
    result = executor.invoke({"input": user_input})
    print(result["output"])
