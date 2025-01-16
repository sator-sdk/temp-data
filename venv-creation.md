# Python venv types and creation

## virtualenv

```shell
# pip install virtualenv
virtualenv v_name
source v_name/bin/activate
deactivate
rm -rf v_name
```

## venv

```shell
python -m venv v_name

rm -rf v_name
```

## poetry

```shell
sudo apt install pipx
pipx ensurepath
# OR
python3 -m pip install --user pipx
python3 -m pipx ensurepath


pipx install poetry
pipx upgrade poetry
pipx uninstall poetry
```

```shell
poetry new poetry-demo
# from a preexisting project - interactive creation
poetry init

# from inside project folder activate the virtual env
poetry shell
# specific type of python version
poetry env use python3.7
# info
poetry env list
ls /home/user/.cache/pypoetry/virtualenvs 
poetry env info
# deactivate/exit current virtual env
exit
# Delete
poetry env remove <virtualenv_name>


# add deps to project (should also auto installing them as with pip so run this when in the venv)
poetry add <dep_name>
# remove deps
poetry remove <package-name>
# lsit deps
poetry show
# Updating Dependencies
poetry update

# install in virt env
poetry install
# Run programs and perform operations in the scope of a virtual environment
poetry run python script.py


# create requirements.txt from .lock file
poetry export --output requirements.txt


# Build
## When you are ready to ship your project, you can create a distributable package. Poetry facilitates this with a few commands:
poetry build
## This command will create a source distribution and a wheel file in the dist/ directory. These files can be shared or uploaded to a package index like PyPI.
## Users can install your package via pip:
pip install path/to/your_package.whl
```

Excluding `__pycache__` from Version Control

When uploading to GitHub or any other version control system, you should exclude `__pycache__` and .pyc files. To do this, add an entry to your .gitignore file:

```shell
# Ignore Python cache directories and files
__pycache__/
*.pyc
*.pyo
```

This ensures that these files and directories won’t be tracked by Git, keeping your repository clean and free of unnecessary files.

---

### Clear cache

Steps to Manually Clear the Cache

For Unix-based systems (Linux/Mac):

```shell
find . -name "__pycache__" -type d -exec rm -r {} +
```

For Windows:

```cmd
Get-ChildItem -Recurse -Directory -Filter "__pycache__" | Remove-Item -Recurse -Force
```

Clear Bytecode Cache with pyclean (Python 3.8+):

Python 3.8 introduced the pyclean command, which can be used to remove bytecode caches from a specified directory.

```shell
python -m py_compile --clear <directory>
```

Replace <directory> with the path of your project. This will remove all .pyc files recursively from the specified directory.


---

### Clearing Specific Poetry Cache Types

If you want to clear specific cache types or limit the scope:

PyPI Packages:

```shell
poetry cache clear pypi --all
```
Source Packages:

```shell
poetry cache clear source --all
```
Virtual Environments (cached virtual environments created by Poetry):

```shell
poetry cache clear virtualenvs --all
```
