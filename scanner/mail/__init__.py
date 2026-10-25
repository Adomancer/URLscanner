"""E-mail threat analysis: scores whole messages (sender, text, links, attachments, QR codes).

Links found in mail are only analysed passively unless the user explicitly asks for a deep scan, so
merely scanning an inbox never tells a sender that a message was opened.
"""
