import sys
import json
from scrapling import Adaptor
import base64
import re
from bs4 import BeautifulSoup

def overrite(issue_tags, vuln_data_item, soup_object):
    pocs_to_process = []

    # Aggrega tutte le PoC in un'unica lista
    if vuln_data_item.get("children"):
        for child in vuln_data_item["children"]:
            pocs_to_process.extend(child.get("pocs", []))
    else:
        pocs_to_process = vuln_data_item.get("pocs", [])

    if not pocs_to_process:
        return

    all_reqres_tags = []
    for issue in issue_tags:
        all_reqres_tags.extend(issue.find_all("requestresponse"))

    poc_pairs = list(zip(pocs_to_process[::2], pocs_to_process[1::2]))

    updated_count = 0
    created_count = 0

    if not issue_tags:
        print(f"  - ❌ ERRORE: Nessun issue tag fornito per '{vuln_data_item['title']}'.")
        return

    last_issue_tag = issue_tags[-1]

    for i, (poc_request, poc_response) in enumerate(poc_pairs):
        if i < len(all_reqres_tags):
            tag_container = all_reqres_tags[i]
            request_tag = tag_container.find('request')
            response_tag = tag_container.find('response')

            if not request_tag:
                request_tag = soup_object.new_tag("request", attrs={'base64': 'true'})
                tag_container.append(request_tag)
            if not response_tag:
                response_tag = soup_object.new_tag("response", attrs={'base64': 'true'})
                tag_container.append(response_tag)

            request_tag.string = poc_request
            response_tag.string = poc_response
            updated_count += 1
        else:
            new_rr_tag = soup_object.new_tag("requestresponse")

            new_req_tag = soup_object.new_tag("request", attrs={'base64': 'true'})
            new_req_tag.string = poc_request

            new_resp_tag = soup_object.new_tag("response", attrs={'base64': 'true'})
            new_resp_tag.string = poc_response

            new_rr_tag.append(new_req_tag)
            new_rr_tag.append(new_resp_tag)

            last_issue_tag.append(new_rr_tag)
            created_count += 1

    total_written = updated_count + created_count
    if total_written > 0:
        print(f"  - ✅ Per '{vuln_data_item['title']}': {total_written} coppia/e di PoC scritte.")


def main():
    vulnerabilities_data = []
    i = 1

    if len(sys.argv) != 3:
        print("Uso: python processa_report.py <file.html> <file.xml>")
        sys.exit(1)

    if sys.argv[1].lower().endswith('.html'):
        file_html_path = sys.argv[1]
        file_xml_path = sys.argv[2]
    elif sys.argv[2].lower().endswith('.html'):
        file_html_path = sys.argv[2]
        file_xml_path = sys.argv[1]
    else:
        print("Errore: È necessario fornire un file .html e un file .xml.")
        sys.exit(1)

    print("--- Inizio Elaborazione ---")
    print(f"File HTML in input: {file_html_path}")
    print(f"File XML da modificare: {file_xml_path}")

    try:
        with open(file_html_path, "r", encoding='utf-8') as report_html_file:
            html_content = report_html_file.read()
        with open(file_xml_path, "r", encoding='utf-8') as report_xml_file:
            xml_content = report_xml_file.read()
    except FileNotFoundError as e:
        print(f"Errore: File non trovato - {e}")
        sys.exit(1)

    page2 = BeautifulSoup(xml_content, 'xml')
    page = Adaptor(html_content)

    print("\n--- Estrazione dati dal file HTML ---")
    while True:
        main_vuln_element = page.xpath_first(f'//span[@id="{i}"]')
        if main_vuln_element is None:
            break

        parent_vulnerability = {
            "id": str(i),
            "title": main_vuln_element.css_first('a').text,
            "children": [],
            "pocs": []
        }

        first_child_element = page.xpath_first(f'//span[@id="{i}.1"]')
        if first_child_element is not None:
            j = 1
            while True:
                child_element = page.xpath_first(f'//span[@id="{i}.{j}"]')
                if child_element is None:
                    break

                pocs = []
                for sibling in child_element.xpath('./following-sibling::*'):
                    if sibling.attrib.get('id'):
                        break
                    if sibling.xpath('self::div[@class="rr_div"]'):
                        span_html_content = sibling.html_content.replace('<br>', '\n')
                        clean_text = re.sub(r"<[^>]*>", "", span_html_content).strip()
                        if clean_text:
                            base64_poc = base64.b64encode(clean_text.encode('utf-8')).decode('utf-8')
                            pocs.append(base64_poc)

                child_data = { "pocs": pocs }
                parent_vulnerability["children"].append(child_data)
                j += 1
        else:
            for sibling in main_vuln_element.xpath('./following-sibling::*'):
                if sibling.attrib.get('id'):
                    break
                if sibling.xpath('self::div[@class="rr_div"]'):
                    span_html_content = sibling.html_content.replace('<br>', '\n')
                    clean_text = re.sub(r"<[^>]*>", "", span_html_content).strip()
                    if clean_text:
                        base64_poc = base64.b64encode(clean_text.encode('utf-8')).decode('utf-8')
                        parent_vulnerability["pocs"].append(base64_poc)

        vulnerabilities_data.append(parent_vulnerability)
        i += 1

    print("\n--- Corrispondenza e aggiornamento dati nel file XML ---")
    for vuln_data_item in vulnerabilities_data:
        vulnerability_title = vuln_data_item['title']

        name_tags_found = page2.find_all('name', string=vulnerability_title)

        if name_tags_found:
            issue_tags_to_modify = [tag.parent for tag in name_tags_found]
            overrite(issue_tags_to_modify, vuln_data_item, page2)
        else:
            print(f"  - ⚠️  ATTENZIONE: Nessun tag <issue> trovato per '{vulnerability_title}'.")

    with open(file_xml_path, "w", encoding='utf-8') as f:
        f.write(str(page2))

    print(f"\n--- Elaborazione Terminata ---")
    print(f"File XML '{file_xml_path}' è stato aggiornato con successo.")


if __name__ == '__main__':
    main()
