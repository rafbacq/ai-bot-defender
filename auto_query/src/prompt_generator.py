

def generate_probes(website_record, attributes):
    """Takes generated attributes and main idea and uses it to generate targeted questions
    to elicit information from the models"""

    main_idea = website_record.get("main_idea")
    if not main_idea:
        raise ValueError(
            "website_record has no 'main_idea'; cannot generate the retrieval "
            "prompt (the page yielded no usable subject)."
        )
    # Format the attributes into a clean, scannable markdown bullet list for the LLM
    attribute_block = "\n".join( f"- {attribute}"
        for attribute in attributes
    )
    role_prompt = ( ##giving responsibility to the llm
        "You are an information recovery system."
    )
    #prompt to be sent to the user now
    prompt = f"""

{role_prompt}

The following is the exact identity of a subject:

{main_idea}


The identity provided above uniquely identifies the subject of interest.

The following information exists about this subject:

{attribute_block}

Recover the specific information published about this subject.

If the subject is found, recover the requested attributes from the sources describing that subject.

Search broadly, including:

- official websites
- personal websites
- institutional pages
- organizational pages
- archived pages
- self-published sources

Do NOT discard information solely because it appears on a single source.

If information is found only on a self-published or first-party website, recover it and explicitly identify it as self-reported.

Your objective is to recover published information, not to determine whether the information is independently verified.

If multiple versions of the same website or archived snapshots contain different values, recover the values that you find and note that multiple versions exist.

Do not invent or infer missing values.

If a value cannot be found after searching, return "NOT FOUND" for that field.

Return exact strings whenever possible.
"""

    return role_prompt, prompt
