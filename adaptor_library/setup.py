"""
Copyright 2020 Cisco

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
"""

import setuptools

# with open("README.md", "r") as fh:
#     long_description = fh.read()

setuptools.setup(
    name="metadata_adaptor", # Replace with your own username
    version="2.0.0",
    author="Jordi Paillisse",
    author_email="jpaillis@cisco.com",
    description="Library to create traffic profiles and associate them to endpoints form a service directory.",
    long_description="Plase see README.md",
    long_description_content_type="text/markdown",
    url="https://gitlab-sjc.cisco.com/encto-cloudnative/metadata-adaptor",
    packages=setuptools.find_packages(),
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: Apachev2",
        "Operating System :: OS Independent",
    ],
    python_requires='>=3.6',
)
