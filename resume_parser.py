import fitz  # PyMuPDF for extracting text from PDFs
import string
from rapidfuzz import fuzz, process

# Expanded skills list
JOB_DESCRIPTION_SKILLS = {
    "python", "flask", "sql", "machine learning", "deep learning", "nlp", "azure", "django", 
    "tensorflow", "pytorch", "pandas", "numpy", "fastapi", "langchain", "hugging face", "transformers",
    "vector databases", "qdrant", "faiss", "streamlit", "autogen", "vanna.ai", "git", "docker"
}

def extract_text_from_pdf(pdf_path):
    """Extract text from a PDF file"""
    try:
        doc = fitz.open(pdf_path)
        text = " ".join(page.get_text("text") for page in doc)
        return text.lower()
    except Exception as e:
        print(f"Error reading {pdf_path}: {e}")
        return ""

def preprocess_text(text):
    """Tokenize and clean text"""
    words = text.split()
    words = [word.strip(string.punctuation) for word in words]
    return set(words)

def fuzzy_match_skills(resume_skills, job_skills, threshold=80):
    """Finds fuzzy matches for skills using RapidFuzz"""
    matched_skills = set()
    for skill in resume_skills:
        best_match, score, _ = process.extractOne(skill, job_skills, scorer=fuzz.ratio)
        if score >= threshold:
            matched_skills.add(best_match)
    return matched_skills

def process_resume(pdf_path):
    """Extract and match skills from a resume"""
    resume_text = extract_text_from_pdf(pdf_path)
    words = preprocess_text(resume_text)
    matched_skills = fuzzy_match_skills(words, JOB_DESCRIPTION_SKILLS)
    
    match_percentage = (len(matched_skills) / len(JOB_DESCRIPTION_SKILLS)) * 100 if JOB_DESCRIPTION_SKILLS else 0
    return matched_skills, match_percentage
