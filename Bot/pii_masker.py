from presidio_analyzer import AnalyzerEngine, Pattern, PatternRecognizer
from presidio_anonymizer import AnonymizerEngine
from presidio_anonymizer.entities import OperatorConfig

#Analyzer setup 
analyzer = AnalyzerEngine()  

#Custom recognizers
#Upi patterns
upi_pattern = Pattern(name="upi_pattern", regex=r"\b[\w.\-]+@[a-zA-Z]+\b", score=0.9)
upi_recognizer = PatternRecognizer(supported_entity="UPI_ID", patterns=[upi_pattern])

#account number
bankref_pattern = Pattern(name="bankref_pattern", regex=r"\b\d{10,}\b", score=0.85)
bankref_recognizer = PatternRecognizer(supported_entity="BANK_REF", patterns=[bankref_pattern])
account_pattern = Pattern(name="account_pattern", regex=r"[A-Za-z]+ Bank\s*[•\-]*\d{2,6}", score=0.85)
account_recognizer = PatternRecognizer(supported_entity="BANK_ACCOUNT", patterns=[account_pattern])

# Amount
amount_pattern = Pattern(name="amount_pattern", regex=r"(₹|Rs\.?)\s?\d+(\.\d{1,2})?", score=0.85)
amount_recognizer = PatternRecognizer(supported_entity="AMOUNT", patterns=[amount_pattern])

analyzer.registry.add_recognizer(upi_recognizer)
analyzer.registry.add_recognizer(bankref_recognizer)
analyzer.registry.add_recognizer(account_recognizer)
analyzer.registry.add_recognizer(amount_recognizer)
anonymizer = AnonymizerEngine()

#custom and built in entities
ENTITIES = [
    "PERSON",
    "PHONE_NUMBER",
    "EMAIL_ADDRESS",
    "UPI_ID",
    "BANK_REF",
    "BANK_ACCOUNT",
    "AMOUNT",
]

# How each entity type should be masked
OPERATORS = {
    "PERSON": OperatorConfig("replace", {"new_value": "<NAME>"}),
    "PHONE_NUMBER": OperatorConfig("replace", {"new_value": "<PHONE>"}),
    "EMAIL_ADDRESS": OperatorConfig("replace", {"new_value": "<EMAIL>"}),
    "UPI_ID": OperatorConfig("mask", {"masking_char": "*", "chars_to_mask": 6, "from_end": False}),
    "BANK_REF": OperatorConfig("replace", {"new_value": "<BANK_REF>"}),
    "BANK_ACCOUNT": OperatorConfig("replace", {"new_value": "<BANK_ACCOUNT>"}),
    "AMOUNT": OperatorConfig("replace", {"new_value": "<AMOUNT>"}),
}


def mask_text(text):
    if not text:
        return text
    results = analyzer.analyze(text=text, entities=ENTITIES, language="en")
    masked = anonymizer.anonymize(text=text, analyzer_results=results, operators=OPERATORS)
    return masked.text