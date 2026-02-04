import sys
from markdown_it import MarkdownIt
from pygments import highlight
from pygments.lexers import get_lexer_by_name, guess_lexer
from pygments.formatters import HtmlFormatter
from weasyprint import HTML, CSS

# --- CONFIGURATION COULEURS ---
STYLE_THEME = 'monokai'
VSCODE_BG = "#1e1e1e"
# ------------------------------

def highlight_code(code, name, attrs):
    try:
        lexer = get_lexer_by_name(name) if name else guess_lexer(code)
    except:
        lexer = get_lexer_by_name("text")
    
    formatter = HtmlFormatter(style=STYLE_THEME, noclasses=True)
    return highlight(code, lexer, formatter)

def markdown_to_pdf(input_file, output_file):
    try:
        import linkify_it
        enable_linkify = True
    except ImportError:
        enable_linkify = False

    md = MarkdownIt("gfm-like", {
        "linkify": enable_linkify,
        "html": True,
        "highlight": highlight_code
    })

    try:
        with open(input_file, 'r', encoding='utf-8') as f:
            content = f.read()
    except FileNotFoundError:
        print(f"Erreur : Impossible de trouver le fichier '{input_file}'")
        return

    html_body = md.render(content)

    css_content = f"""
    @page {{
        margin: 1.2cm; 
        size: A4;
        @bottom-center {{
            content: "Page " counter(page);
            font-family: 'Segoe UI', sans-serif;
            font-size: 10px;
            color: #888;
        }}
    }}
    body {{
        font-family: 'Segoe UI', 'Roboto', 'Helvetica Neue', sans-serif;
        font-size: 14px;
        line-height: 1.35; 
        color: #333;
        background-color: #fff;
        text-align: justify;
        overflow-wrap: break-word; 
        word-wrap: break-word;     
        hyphens: auto;             
    }}
    a {{
        overflow-wrap: break-word;
        word-break: break-all;
        color: #007acc;
        text-decoration: none;
    }}
    h1 {{ 
        font-size: 22px; 
        color: #19242E; 
        border-bottom: 3px solid #eee; 
        padding-bottom: 5px;
        margin-top: 0;
        margin-bottom: 15px; 
    }}
    h2 {{ 
        font-size: 17px; 
        color: #2c3e50; 
        margin-top: 20px; 
        margin-bottom: 10px;
        border-bottom: 1px solid #eee; 
        padding-bottom: 3px;
    }}
    h3 {{ 
        font-size: 15px; 
        color: #3A5269; 
        margin-top: 15px;
        margin-bottom: 8px; 
    }}
    pre {{
        background-color: {VSCODE_BG}; 
        color: #d4d4d4;
        padding: 10px; 
        border-radius: 6px;
        border: 1px solid #3c3c3c;
        font-family: 'Fira Code', 'Consolas', 'Courier New', monospace;
        font-size: 0.75em; 
        line-height: 1.3; 
        margin: 15px 0;   
        overflow-x: hidden;
        white-space: pre-wrap;
        overflow-wrap: break-word;
    }}
    code {{
        font-family: 'Fira Code', 'Consolas', monospace;
        background-color: #f3f4f4;
        padding: 2px 4px;
        border-radius: 4px;
        color: #e01e5a;
        font-size: 0.9em;
        overflow-wrap: break-word; 
    }}
    pre code {{
        background-color: transparent;
        color: inherit;
        padding: 0;
        font-size: 1em;
    }}
    blockquote {{
        border-left: 4px solid #007acc;
        background: #f9f9f9;
        margin: 1em 0;
        padding: 8px 15px;
        font-style: italic;
        color: #555;
    }}
    table {{
        width: 100%;
        border-collapse: collapse;
        margin: 15px 0;
        font-size: 0.95em;
        table-layout: fixed;
    }}
    .center {{
        text-align: center;
        display: block;
        margin: 10px 0; 
        width: 100%;
    }}
    th, td {{ 
        padding: 8px; 
        border: 1px solid #ddd; 
        overflow-wrap: break-word;
    }}
    th {{ background-color: #f8f9fa; font-weight: bold; text-align: left; }}
    p {{ margin-bottom: 10px; }} 
    img {{ max-width: 100%; height: auto; display: block; margin: 15px auto; border-radius: 5px; }}
    """

    full_html = f"""
    <!DOCTYPE html>
    <html>
    <head><meta charset="UTF-8"></head>
    <body>{html_body}</body>
    </html>
    """

    print(f"Conversion de '{input_file}' en cours...")
    try:
        html_obj = HTML(string=full_html, base_url=".")
        css_obj = CSS(string=css_content)
        html_obj.write_pdf(output_file, stylesheets=[css_obj])
        print(f"Fichier PDF généré : {output_file}")
    except Exception as e:
        print(f"Erreur WeasyPrint : {e}")

if __name__ == "__main__":
    if len(sys.argv) > 1:
        filename = sys.argv[1]
        output_name = filename.rsplit('.', 1)[0] + ".pdf"
        markdown_to_pdf(filename, output_name)
    else:
        print("Usage: python md_to_pdf.py mon_fichier.md")