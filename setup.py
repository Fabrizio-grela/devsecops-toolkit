from setuptools import setup, find_packages

with open("requirements.txt", "r", encoding="utf-8") as f:
    requirements = f.read().splitlines()

setup(
    name="devsecops-toolkit", # Puedes cambiarlo si el nombre ya está registrado en PyPI
    version="2.0.0",
    author="Fabrizio",
    description="Suite de seguridad modular en Python para análisis estático y detección de amenazas.",
    long_description=open("readme.md", "r", encoding="utf-8").read(),
    long_description_content_type="text/markdown",
    packages=find_packages(),
    py_modules=['main', 'utils', 'config_manager', 'report_generator', 'ai_handler'],
    install_requires=requirements,
    entry_points={
        'console_scripts': [
            'devsec=main:main',
        ],
    },
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
    python_requires='>=3.9',
)