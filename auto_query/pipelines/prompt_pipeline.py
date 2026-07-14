from auto_query.src.parser import parser
from auto_query.src.template_analyzer import analyze_template
from auto_query.src.attribute_generator import generate_attributes
from auto_query.src.prompt_generator import generate_probes

def generate_prompt_pipeline(html, faker_template, rendered_html=None):
    """
    Generates everything required for querying an LLM.

    Parameters
    ----------
    html : str
        HTML source of the synthetic website.

    faker_template : str
        Contents of the corresponding Faker template (.txt).

    rendered_html : str, optional
        Integration addition: the page as a visitor actually sees it. When the
        source ``html`` is a template whose title/headings are ``{{ varN }}``
        placeholders, the subject (``main_idea``) can't come from it — pass the
        rendered page here and the parser reads the subject from that, while
        template analysis still runs on the placeholder ``html``.

    Returns
    -------
    dict
        {
            "website_record": ...,
            "template_analysis": ...,
            "attributes": ...,
            "role_prompt": ...,
            "prompt": ...
        }
    """

    #get main idea of website
    website_record = parser(rendered_html or html)


    #generates attributes to make the prompt targeted at an answer
    template_analysis = analyze_template(html)
    attributes = generate_attributes(template_analysis["variables"])

    #actual prompt
    role_prompt, prompt = generate_probes(website_record,attributes)

    #dictionary of output for every step
    return {

        "website_record":
            website_record,

        "template_analysis":
            template_analysis,

        "attributes":
            attributes,

        "role_prompt":
            role_prompt,

        "prompt":
            prompt,

        "faker_template":
            faker_template
    }
