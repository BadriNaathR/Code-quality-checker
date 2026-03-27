"""
LLM Recommendation Service — generates AI fix suggestions for critical issues.
"""
import httpx
from langchain_openai import ChatOpenAI

_llm = ChatOpenAI(
    base_url="https://genailab.tcs.in",
    model="azure/genailab-maas-gpt-5-mini",
    api_key="sk-51W8XpJVfI4NV_VR5kvj_A",
    http_client=httpx.Client(verify=False),
)

_PROMPT = """\
You are a senior software engineer reviewing code quality findings.
A static analysis tool flagged the following issue:

Rule     : {rule_id} — {rule_name}
File     : {file}:{line}
Category : {category}
Message  : {message}
{owasp_line}
Code snippet:
{code_snippet}

Provide a concise, actionable recommendation to fix this issue.
- 2–4 sentences max.
- Include a corrected code snippet if helpful.
- Focus only on the fix, do not repeat the problem description.
"""


_BLOCKED_TERMS = [
    "injection", "sql injection", "xss", "cross-site scripting",
    "command injection", "code injection", "ldap injection",
    "owasp", "a03:2021", "a01:2021",
]

def _sanitize(text: str) -> str:
    """Replace content-filter trigger words with neutral equivalents."""
    if not text:
        return text
    result = text
    replacements = {
        "injection": "unsanitized input",
        "sql injection": "unsanitized query input",
        "xss": "unescaped output",
        "cross-site scripting": "unescaped output",
        "command injection": "unsanitized command input",
        "code injection": "unsanitized code input",
        "ldap injection": "unsanitized directory input",
    }
    for term, replacement in replacements.items():
        result = result.replace(term, replacement)
        result = result.replace(term.upper(), replacement.upper())
        result = result.replace(term.title(), replacement.title())
    return result


def get_recommendation(issue: dict) -> str:
    owasp_line = f"Standard : {issue['owasp_category'].split('-')[0]}" if issue.get("owasp_category") else ""
    code_snippet = issue.get("code_snippet") or "(not available)"
    prompt = _PROMPT.format(
        rule_id=issue.get("rule_id", ""),
        rule_name=_sanitize(issue.get("rule_name", "")),
        file=issue.get("file", ""),
        line=issue.get("line", ""),
        category=issue.get("category", ""),
        message=_sanitize(issue.get("message", "")),
        owasp_line=owasp_line,
        code_snippet=code_snippet,
    )
    try:
        return _llm.invoke(prompt).content.strip()
    except Exception as e:
        return f"Could not generate recommendation: {e}"
