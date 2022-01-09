PROJECT := utilities


# virtualenv:
# 	python3 -m venv ./venv && source venv/bin/activate

# setup-env: virtualenv
# 	python3 -m pip install -r ./cloud/requirements.txt
# 	python3 -m pip install -r ./messaging/requirements.txt

build: uninstall clean
	python3 -m pip install --upgrade setuptools wheel
	python3 -m setup -q sdist bdist_wheel


install: build
	python3 -m pip install -q ./dist/${PROJECT}*.tar.gz


clean:
	rm -rf dist/
	rm -rf build/
	rm -rf *.egg-info
	find . -name '*.pyc' -delete
	find . -name '*.pyo' -delete
	find . -name '*.egg-link' -delete
	find . -name '*.pyc' -exec rm --force {} +
	find . -name '*.pyo' -exec rm --force {} +

uninstall:
	python3 -m pip uninstall ${PROJECT} -y