# jbb-data
Fetch and curate species list for the JBB

https://florabog.jbb.gov.co

https://florabog.jbb.gov.co/files/Lista_taxones_FdBog_v1.4_20241130.xlsx

## Pipeline

Extract the scientific names and run gnverifier:

```sh
python3 scripts/resolve_taxa.py
```

Outputs:
- `data/Lista_taxones_FdBog_v1.4_20241130.xlsx`
- `data/nombres_cientificos.txt`
- `data/gnverifier_results.csv`
- `data/gnverifier_merged.csv`
