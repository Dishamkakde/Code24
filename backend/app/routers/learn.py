from fastapi import APIRouter
from typing import List
from app.models.schemas import LearnConcept

router = APIRouter(prefix="/api/learn", tags=["learn"])

LEARN_CONCEPTS: List[LearnConcept] = [
    LearnConcept(
        id="sql-injection",
        title="Tricking the Database (SQL Injection)",
        cwe="CWE-89",
        analogy_title="The Restaurant Order Pad Prank",
        analogy="Imagine a customer writing on a restaurant order ticket: '1 Cheeseburger; ALSO give everyone in the whole diner a free dessert!'. If the cook simply obeys whatever words are written on the slip without realizing it's an instruction rather than a meal name, the diner loses all its sweets! That is SQL injection.",
        why_it_happens="When web apps stick visitor text straight into database commands with f\"SELECT ... {user_input}\", the database cannot tell where your command stops and where the visitor's text begins.",
        how_to_prevent="Always use 'Parameterized Queries' (placeholders like ? or %s). This tells the database: 'Treat this strictly as plain text, never as commands to obey.'",
        simple_example_bad='db.execute(f"SELECT * FROM users WHERE name = \'{user}\'")',
        simple_example_good='db.execute("SELECT * FROM users WHERE name = ?", (user,))',
        icon="Database"
    ),
    LearnConcept(
        id="idor",
        title="Peeking into Other People's Rooms (Broken Access Control)",
        cwe="CWE-639",
        analogy_title="The Hotel Keycard Number Swap",
        analogy="Imagine a hotel where keycards have the room number handwritten with a pencil. If a mischievous guest erases room '104' and writes room '301', and the door lock just lets them in without checking if they actually paid for room 301, any guest can enter any other bedroom!",
        why_it_happens="The code asks the database for an item by its ID (like note_id = 5) but forgets to check: 'Does this item belong to the person currently logged in?'.",
        how_to_prevent="Always verify ownership in every request: check that owner_id matches the current user ID before showing or updating private data.",
        simple_example_bad='db.execute("SELECT * FROM notes WHERE id = ?", (note_id,))',
        simple_example_good='db.execute("SELECT * FROM notes WHERE id = ? AND owner_id = ?", (note_id, current_user_id))',
        icon="Lock"
    ),
    LearnConcept(
        id="path-traversal",
        title="Escaping the Public Folder (Path Traversal)",
        cwe="CWE-22",
        analogy_title="The Sneaky Library Request",
        analogy="Imagine asking a library assistant: 'Please bring me the document named ../../office_safe/confidential_files.txt'. If the assistant follows the '../' symbols literally, they climb out of the reading room and break into the director's locked safe!",
        why_it_happens="In operating systems, the characters '../' mean 'go to the parent folder'. If a website accepts filenames from users without checking where they lead, users can read secret system files and passwords.",
        how_to_prevent="Use path validation (like os.path.realpath and os.path.commonpath) to verify that the final file path really stays inside your allowed folder.",
        simple_example_bad='open(os.path.join(UPLOADS_DIR, filename), "r")',
        simple_example_good='real = os.path.realpath(os.path.join(UPLOADS, filename))\nif os.path.commonpath([real, UPLOADS]) == UPLOADS: ...',
        icon="FolderAlert"
    ),
    LearnConcept(
        id="xss",
        title="Sneaking Script Into Guestbooks (Cross-Site Scripting)",
        cwe="CWE-79",
        analogy_title="The Graffiti on the Town Bulletin Board",
        analogy="Imagine a public community bulletin board where people can pin notes. A prankster pins a note that has invisible ink that forces anyone who reads it to hand over their lunch money. In web apps, if you display visitor comments without escaping HTML, their browser will execute malicious JavaScript.",
        why_it_happens="User comments containing <script> tags or harmful HTML attributes are printed directly into web pages.",
        how_to_prevent="Always escape or encode user input, and use modern frameworks like React that automatically sanitize text content.",
        simple_example_bad='<div>{innerHTML: userComment}</div>',
        simple_example_good='<div>{userComment}</div>  {/* React automatically escapes text */}',
        icon="Code"
    )
]

@router.get("", response_model=List[LearnConcept])
async def get_learn_concepts():
    return LEARN_CONCEPTS
