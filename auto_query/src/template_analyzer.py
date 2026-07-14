
import re
from bs4 import BeautifulSoup
from collections import defaultdict
from pprint import pprint


def analyze_template(html):
    """Parses a HTML template, 
    locate template variables formatted like {{ var1 }} or {{ var2 }},
    extracts their structural context (the text surrounding them and the heading hierarchy they sit under).
"""
    profiles = build_variable_profiles(html)

    return {
        "variable_count":
            len(profiles),

        "variables":
            profiles
    }

# locate variables in template
VARIABLE_PATTERN = re.compile(r"\{\{\s*(var\d+)\s*\}\}")

# replace variables with blanks
def mask_variables(text):
    return re.sub(r"\{\{\s*var\d+\s*\}\}", "_____",text)

# clean html -> text
def clean_html_text(html_fragment):
    soup = BeautifulSoup(html_fragment,"html.parser")
    text = soup.get_text(" ", strip=True)#remove whitespace
    text = " ".join(text.split()) #normalized text
    return text


# find best semantic container
def find_context_container(element):#nearest to the variable
    current = element
    while current:
        if (current.name in["p","li","section","article","div"]):
            return current
        current = current.parent

    return element


#gathers surrounding text for every variable found
def extract_variable_context(html):
    soup = BeautifulSoup(html,"html.parser")

    results = []

    for text_node in soup.find_all(string=True):

        if "{{" not in text_node:
            continue

        variables = VARIABLE_PATTERN.findall(text_node)

        if not variables:
            continue

        container = find_context_container(text_node.parent)

        context = clean_html_text(str(container))

        context = mask_variables(context)

        for variable in variables:
            results.append({

                "variable":
                    variable,

                "context":
                    context

            })

    return results

def get_heading_hierarchy(element): #marker of where the variable sits on the template - what major headings

    headings = {
        "h1": None,
        "h2": None,
        "h3": None
    }

    current = element

    while current:

        previous_heading = current.find_previous(
            ["h1", "h2", "h3"]
        )

        if not previous_heading:
            break

        level = previous_heading.name

        if headings[level] is None:

            headings[level] = (
                previous_heading.get_text(
                    " ",
                    strip=True
                )
            )

        current = previous_heading

    return headings


# associate variables with headings

def extract_variable_sections(html):

    soup = BeautifulSoup(html,"html.parser")

    results = []

    for text_node in soup.find_all(string=True):

        if "{{" not in text_node:
            continue

        variables = VARIABLE_PATTERN.findall(
            text_node
        )

        for variable in variables:

            headings = get_heading_hierarchy(
                text_node.parent
            )

            results.append({

                "variable":
                    variable,

                "headings":
                    headings

            })

    return results


#merges context text and heading data into one dictionary

def build_variable_profiles(html):

    contexts = extract_variable_context(html)

    sections = extract_variable_sections(html)

    merged = defaultdict(dict)

    for item in contexts:

        merged[item["variable"]]["context"] = item["context"]

    for item in sections:

        merged[item["variable"]]["headings"] = item["headings"]

    profiles = []

    for variable, data in merged.items():

        profiles.append({

            "variable":
                variable,

            "headings":
                data.get(
                    "headings",
                    {}
                ),

            "context":
                data.get(
                    "context",
                    ""
                )

        })

    return sorted(

        profiles,

        key=lambda profile: #sorts numerically var 1- var 10
            int(profile["variable"].replace("var", ""))

    )


