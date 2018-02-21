# -*- coding: utf-8 -*-
#!/usr/bin/env python
from app import app
from flask_script import Manager

manage = Manager(app)

if __name__ == "__main__":
    manage.run()
