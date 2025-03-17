#!/usr/bin/python3
import argparse
import os
import requests
import re
import urllib.parse
import datetime
import base64

GITHUB_API_URL = "https://api.github.com/search/code"


def search_github(org):
    token = os.getenv("GITHUB_TOKEN")
    if not token:
        print("Error: GITHUB_TOKEN environment variable is not set.")
        return

    all_matches_from_all_content = []

    query = "uses: language:YAML path:.github/" + f" user:{org}"

    regex_filter = rf"\suses:\s*(?!\s*({org}|github|actions|\./\.github)/)"

    headers = {
        "Authorization": f"token {token}",
        "Accept": "application/vnd.github.text-match+json",
    }

    params = {"q": query, "per_page": 100, "page": 1}

    session = requests.Session()
    session.headers.update(headers)

    print(f"Searching GitHub with query: {query}")

    while True:
        response = session.get(GITHUB_API_URL, params=params)
        if response.status_code != 200:
            print(f"GitHub API Error: {response.status_code} - {response.text}")
            break

        data = response.json()
        items = data.get("items", [])

        if not items:
            break

        for item in items:
            repo = item["repository"]["full_name"]
            path = item["path"]

            # Get the file content as item.text_matches only contains the first two results
            file_response = session.get(item["url"])
            b64_content = file_response.json()["content"]
            file_content = base64.b64decode(b64_content).decode("utf-8")

            file_lines = file_content.splitlines()
            for line in file_lines:
                if re.search(regex_filter, line):
                    new_match = {
                        "repo": repo,
                        "path": path,
                        "line": line.replace("- ", "").strip(),
                    }
                    if not line.startswith("#"):
                        all_matches_from_all_content.append(new_match)

        # Pagination
        if "next" in response.links:
            params["page"] += 1
        else:
            break

    return all_matches_from_all_content


def write_markdown_summary(output_md, all_matches):
    with open(output_md, "w") as f:

        f.write("# Third-party GitHub Action Audit\n\n")
        f.write(
            "Query run "
            + datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            + ". Results for default branches only.\n\n"
        )

        f.write("## Third party actions\n\n")
        f.write("|Count|Action|\n")
        f.write("|--:|:--|\n")

        from collections import defaultdict

        counts = defaultdict(int)
        for match in all_matches:
            counts[match["line"]] += 1

        sorted_lines = sorted(counts.items(), key=lambda x: x[1], reverse=True)

        for line, count in sorted_lines:
            action = line.replace("uses: ", "")
            # Confluence-compatible anchor link
            anchor = urllib.parse.quote_plus(action.lower())

            f.write(f"|{count}|[{action}](#{anchor})|\n")

        f.write("\n---\n")

        # Table of distinct_count(action) by repo
        f.write("## Number of distinct actions by repo\n\n")
        f.write("|Repository|Unique Actions|\n")
        f.write("|---|--:|\n")

        repo_actions = defaultdict(set)
        for match in all_matches:
            repo_name = match["repo"].split("/")[1]
            action = match["line"].replace("uses: ", "")
            repo_actions[repo_name].add(action)

        sorted_repos = sorted(
            repo_actions.items(), key=lambda x: len(x[1]), reverse=True
        )
        for repo, actions in sorted_repos:
            f.write(f"|{repo}|{len(actions)}|\n")

        f.write("\n---\n")

        f.write("## References per action\n\n")

        unique_lines = set([match["line"] for match in all_matches])
        for line in unique_lines:
            third_party_action = line.replace("uses: ", "")
            f.write(f"\n### {third_party_action}\n\n")
            f.write("|Repository|Path|\n")
            f.write("|---|---|\n")
            for match in all_matches:
                if match["line"] == line:
                    repo_name = match["repo"].split("/")[1]
                    f.write(f"|{repo_name}|{match['path']}|\n")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="GitHub Code Search with Advanced Filtering"
    )

    parser.add_argument("org", help="GitHub organization/user name")
    parser.add_argument(
        "--output-md", help="Output file for markdown summary", required=True
    )
    parser.add_argument("--output-json", help="Optional output file for search results")

    args = parser.parse_args()

    all_matches = search_github(args.org)

    if args.output_json:
        os.makedirs("results", exist_ok=True)
        with open(f"results/{args.output_json}", "w") as f:
            for match in all_matches:
                f.write(f"{match}\n")
        print(f"Results written to results/{args.output_json}\n\n")

    if args.output_md:
        os.makedirs("results", exist_ok=True)
        write_markdown_summary(f"results/{args.output_md}", all_matches)
