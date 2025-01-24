```python
"""Test cases for Snippets."""
from .. import util
import os
from pymdownx.snippets import SnippetMissingError
from unittest.mock import patch, MagicMock

BASE = os.path.abspath(os.path.dirname(__file__))


class TestSnippetDedent(util.MdCase):
    """Test snippet cases."""

    extension = [
        'pymdownx.snippets', 'pymdownx.superfences'
    ]

    extension_configs = {
        'pymdownx.snippets': {
            'base_path': [os.path.join(BASE, '_snippets')],
            'dedent_subsections': True
        }
    }

    def test_dedent_section(self):
        """Test dedenting sections."""

        self.check_markdown(
            R'''
            ```text
            ---8<--- "indented.txt:py-section"
            ```
            ''',  # noqa: W291
            R'''
            <div class="highlight"><pre><span></span><code>def some_method(self, param):
                &quot;&quot;&quot;Docstring.&quot;&quot;&quot;

                return param
            </code></pre></div>
            ''',
            True
        )

    def test_dedent_lines(self):
        """Test dedenting lines."""

        self.check_markdown(
            R'''
            ```text
            ---8<--- "indented.txt:5:8"
            ```
            ''',  # noqa: W291
            R'''
            <div class="highlight"><pre><span></span><code>def some_method(self, param):
                &quot;&quot;&quot;Docstring.&quot;&quot;&quot;

                return param
            </code></pre></div>
            ''',
            True
        )

    def test_dedent_indented(self):
        """Test dedenting sections that has indented insertion."""

        self.check_markdown(
            R'''
            Paragraph

                ---8<--- "indented.txt:py-section"
            ''',  # noqa: W291
            R'''
            <p>Paragraph</p>
            <pre><code>def some_method(self, param):
                """Docstring."""

                return param
            </code></pre>
            ''',
            True
        )


class TestSnippets(util.MdCase):
    """Test snippet cases."""

    extension = [
        'pymdownx.snippets', 'pymdownx.superfences'
    ]

    extension_configs = {
        'pymdownx.snippets': {
            'base_path': [os.path.join(BASE, '_snippets')]
        }
    }

    def test_inline(self):
        """Test inline."""

        self.check_markdown(
            R'''
            ---8<--- "loop.txt"
            ---8<--- "a.txt"
            ---8<--- "b.txt"
            ;---8<--- "b.txt"

            - Testing indentation

                ---8<--- "b.txt"
            ''',  # noqa: W291
            R'''
            <p>Snippet
            Snippet
            ---8&lt;--- "b.txt"</p>
            <ul>
            <li>
            <p>Testing indentation</p>
            <p>Snippet</p>
            </li>
            </ul>
            ''',
            True
        )

    def test_block(self):
        """Test block."""

        self.check_markdown(
            R'''
            ---8<---
            loop_block.txt
            c.txt

            d.txt
            ---8<---

            ;---8<---
            d.txt
            ;---8<---

            - Testing indentation

                ---8<---
                d.txt

                ; d.txt
                # Nested inline won't work
                --8<-- "a.txt"
                --8<-- "; b.txt"
                ---8<---

                # Un-nested Inline
                --8<-- "a.txt"
                --8<-- "; b.txt"
            ''',  # noqa: W291
            R'''
            <p>Snippet</p>
            <p>Snippet</p>
            <p>---8&lt;---
            d.txt
            ---8&lt;---</p>
            <ul>
            <li>
            <p>Testing indentation</p>
            <p>Snippet</p>
            <h1>Un-nested Inline</h1>
            <p>Snippet</p>
            </li>
            </ul>
            ''',  # noqa: W291
            True
        )

    def test_mixed(self):
        """Test mixed."""

        self.check_markdown(
            R'''
            ---8<--- "a.txt"

            ---8<---
            loop_block.txt
            c.txt

            d.txt
            ---8<---
            ''',
            R'''
            <p>Snippet</p>
            <p>Snippet</p>
            <p>Snippet</p>
            ''',
            True
        )

    def test_start_line_inline(self):
        """Test starting line with inline syntax."""

        self.check_markdown(
            R'''
            ---8<--- "lines.txt:4"
            ''',
            '''
            <p>Content resides on various lines.
            If we use line specifiers,
            we can select any number of lines we want.</p>
            <p>This is the end of the file.
            There is no more.</p>
            ''',
            True
        )

    def test_end_line_inline(self):
        """Test ending line with inline syntax."""

        self.check_markdown(
            R'''
            ---8<--- "lines.txt::6"
            ''',
            '''
            <p>This is a multi-line
            snippet.</p>
            <p>Content resides on various lines.
            If we use line specifiers,
            we can select any number of lines we want.</p>
            ''',
            True
        )

    def test_start_end_line_inline(self):
        """Test starting and ending line with inline syntax."""

        self.check_markdown(
            R'''
            ---8<--- "lines.txt:4:6"
            ''',
            '''
            <p>Content resides on various lines.
            If we use line specifiers,
            we can select any number of lines we want.</p>
            ''',
            True
        )

    def test_start_line_block(self):
        """Test starting line with block syntax."""

        self.check_markdown(
            R'''
            --8<--
            lines.txt:4
            --8<--
            ''',
            '''
            <p>Content resides on various lines.
            If we use line specifiers,
            we can select any number of lines we want.</p>
            <p>This is the end of the file.
            There is no more.</p>
            ''',
            True
        )

    def test_end_line_block(self):
        """Test ending line with block syntax."""

        self.check_markdown(
            R'''
            --8<--
            lines.txt::6
            --8<--
            ''',
            '''
            <p>This is a multi-line
            snippet.</p>
            <p>Content resides on various lines.
            If we use line specifiers,
            we can select any number of lines we want.</p>
            ''',
            True
        )

    def test_start_end_line_block(self):
        """Test starting and ending line with block syntax."""

        self.check_markdown(
            R'''
            --8<--
            lines.txt:4:6
            --8<--
            ''',
            '''
            <p>Content resides on various lines.
            If we use line specifiers,
            we can select any number of lines we want.</p>
            ''',
            True
        )

    def test_section_inline(self):
        """Test section partial in inline snippet."""

        self.check_markdown(
            R'''
            ```
            --8<-- "section.txt:css-section"
            ```
            ''',
            '''
            <div class="highlight"><pre><span></span><code>div {
                color: red;
            }
            </code></pre></div>
            ''',
            True
        )

    def test_section_inline_min(self):
        """Test section partial in inline snippet using minimum tokens."""

        self.check_markdown(
            R'''