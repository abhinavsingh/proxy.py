#!/usr/bin/env python3
"""
Automated Translation Script for Clean Code TypeScript
Uses deep-translator library (Google Translate) - FREE!
"""

import sys
import time
from pathlib import Path

from deep_translator import GoogleTranslator


# All supported languages
LANGUAGES = {
    '1': {'name': 'Chinese (Simplified)', 'code': 'zh-CN', 'file': 'README.zh-CN.md'},
    '2': {'name': 'Chinese (Traditional)', 'code': 'zh-TW', 'file': 'README.zh-TW.md'},
    '3': {'name': 'Spanish', 'code': 'es', 'file': 'README.es.md'},
    '4': {'name': 'French', 'code': 'fr', 'file': 'README.fr.md'},
    '5': {'name': 'Portuguese', 'code': 'pt', 'file': 'README.pt-BR.md'},
    '6': {'name': 'German', 'code': 'de', 'file': 'README.de.md'},
    '7': {'name': 'Japanese', 'code': 'ja', 'file': 'README.ja.md'},
    '8': {'name': 'Korean', 'code': 'ko', 'file': 'README.ko.md'},
    '9': {'name': 'Russian', 'code': 'ru', 'file': 'README.ru.md'},
    '10': {'name': 'Italian', 'code': 'it', 'file': 'README.it.md'},
    '11': {'name': 'Arabic', 'code': 'ar', 'file': 'README.ar.md'},
    '12': {'name': 'Hindi', 'code': 'hi', 'file': 'README.hi.md'},
    '13': {'name': 'Turkish', 'code': 'tr', 'file': 'README.tr.md'},
    '14': {'name': 'Vietnamese', 'code': 'vi', 'file': 'README.vi.md'},
    '15': {'name': 'Polish', 'code': 'pl', 'file': 'README.pl.md'},
    '16': {'name': 'Dutch', 'code': 'nl', 'file': 'README.nl.md'},
    '17': {'name': 'Indonesian', 'code': 'id', 'file': 'README.id.md'},
    '18': {'name': 'Thai', 'code': 'th', 'file': 'README.th.md'},
    '19': {'name': 'Swedish', 'code': 'sv', 'file': 'README.sv.md'},
    '20': {'name': 'Greek', 'code': 'el', 'file': 'README.el.md'},
}

def show_languages():
    """Display all available languages"""
    print('=' * 70)
    print('Clean Code TypeScript - Automated Translation')
    print('Using Google Translate (FREE!)')
    print('=' * 70)
    print('\nSelect target language:\n')

    for key, lang in sorted(LANGUAGES.items(), key=lambda x: int(x[0])):
        print(f"  {key:2}. {lang['name']}")

    print("\nEnter choice (1-20) or 'all' for all languages: ", end='')

def select_language():
    """Interactive language selection"""
    show_languages()
    choice = input().strip().lower()

    if choice == 'all':
        return 'all'

    if choice not in LANGUAGES:
        print('❌ Invalid choice!')
        sys.exit(1)

    return [LANGUAGES[choice]]

def translate_text(text, target_lang_code, max_length=4500):
    """Translate text using Google Translate"""
    try:
        # Google Translate has a 5000 char limit per request
        if len(text) > max_length:
            # Split into smaller chunks
            chunks = []
            current = ''

            for line in text.split('\n'):
                if len(current) + len(line) < max_length:
                    current += line + '\n'
                else:
                    if current:
                        chunks.append(current)
                    current = line + '\n'

            if current:
                chunks.append(current)

            # Translate each chunk
            translated_chunks = []
            for chunk in chunks:
                translator = GoogleTranslator(source='en', target=target_lang_code)
                translated = translator.translate(chunk)
                translated_chunks.append(translated)
                time.sleep(0.5)  # Rate limiting

            return '\n'.join(translated_chunks)
        else:
            translator = GoogleTranslator(source='en', target=target_lang_code)
            return translator.translate(text)

    except Exception as e:
        print(f"\n❌ Translation error: {e}")
        return None

def translate_readme(lang_config):
    """Translate the entire README.md file"""
    print(f"\n{'='*70}")
    print(f"Translating to {lang_config['name']}...")
    print('='*70)

    # Read README
    readme_path = Path('README.md')
    if not readme_path.exists():
        print('❌ README.md not found!')
        return False

    with open(readme_path, 'r', encoding='utf-8') as f:
        content = f.read()

    print(f"\n📄 Original: {len(content)} characters")

    # Split into manageable chunks (preserve code blocks)
    chunks = []
    current_chunk = ''
    in_code_block = False

    for line in content.split('\n'):
        # Detect code blocks
        if line.strip().startswith('```'):
            in_code_block = not in_code_block

        # If in code block or chunk is small enough, add line
        if in_code_block or len(current_chunk) + len(line) < 4000:
            current_chunk += line + '\n'
        else:
            if current_chunk:
                chunks.append(current_chunk)
            current_chunk = line + '\n'

    if current_chunk:
        chunks.append(current_chunk)

    print(f"📦 Split into {len(chunks)} chunks")
    print(f"\n🔄 Translating...\n")

    # Translate each chunk
    translated_chunks = []

    for i, chunk in enumerate(chunks, 1):
        print(f"[{i}/{len(chunks)}] Chunk {i}... ", end='', flush=True)

        translated = translate_text(chunk, lang_config['code'])

        if translated:
            translated_chunks.append(translated)
            print(f"✅")
        else:
            print('❌ Failed!')
            return False

        time.sleep(1)  # Rate limiting

    # Combine
    final_translation = '\n'.join(translated_chunks)

    # Save
    output_path = Path(lang_config['file'])
    with open(output_path, 'w', encoding='utf-8') as f:
        f.write(final_translation)

    print(f"\n✅ Saved to {output_path}")
    print(f"📊 Size: {len(final_translation)} characters")

    return True

def main():
    # Check if deep-translator is installed
    try:
        from deep_translator import GoogleTranslator
    except ImportError:
        print('❌ deep-translator not installed!')
        print('📦 Install with: pip install deep-translator')
        sys.exit(1)

    # Select language(s)
    selection = select_language()

    if selection == 'all':
        print(f"\n✨ Translating to ALL {len(LANGUAGES)} languages!")
        print('⚠️  This will take a while...\n')

        print('Proceed? (y/n): ', end='')
        if input().strip().lower() != 'y':
            print('❌ Cancelled')
            sys.exit(0)

        languages_to_translate = list(LANGUAGES.values())
    else:
        languages_to_translate = selection
        print(f"\n✨ Selected: {languages_to_translate[0]['name']}")
        print(f"📁 Output: {languages_to_translate[0]['file']}\n")

        print('Proceed? (y/n): ', end='')
        if input().strip().lower() != 'y':
            print('❌ Cancelled')
            sys.exit(0)

    # Translate
    success_count = 0
    for lang_config in languages_to_translate:
        if translate_readme(lang_config):
            success_count += 1
        print()

    # Summary
    print('=' * 70)
    print(f"✅ Completed: {success_count}/{len(languages_to_translate)} translations")
    print('=' * 70)

    if success_count > 0:
        print(f"\n💡 Next steps:")
        print(f"   1. Review translated files")
        print(f"   2. git add README.*.md")
        print(f"   3. git commit -m 'Add translations - Fixes #15'")
        print(f"   4. Create PR")

if __name__ == '__main__':
    main()
