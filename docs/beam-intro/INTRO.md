## Introduction to Beam

This document details a small workshop that can be run through to get familiar with building
pipelines in Beam.

### Getting started

Fetch the [foxsec-pipeline](https://github.com/mozilla-services/foxsec-pipeline) repo.

```
git clone https://github.com/mozilla-services/foxsec-pipeline.git
```

Build the docker images.

```
docker build -f Dockerfile-base -t foxsec-pipeline-base:latest .
```

Run a simple parser test just to make sure your environment is working correctly. This will also
fetch all required dependencies from central at the Maven Repository.

```
bin/m test -Dtest=ParserTest
```

All pipeline testing will run in the docker container for the workshop, and no dependencies
are required locally with the exception of docker. The script `bin/m` simply calls docker
to create a new container, executes the pipeline, and removes the container afterwards.

### Objective

* Create a Beam pipeline to print the number of times each word occurs in the script for [Star Trek II: The Wrath of Khan](https://www.imdb.com/title/tt0084726/).
* Optional: also calculate and print the average number of occurences for all words.

### Instructions

An initial pipeline class has been created at [../../src/main/java/com/mozilla/secops/workshop/Workshop.java](../../src/main/java/com/mozilla/secops/workshop/Workshop.java). This is the only file you will be required to edit.

The input has already been setup in the class to read the input data.

Placeholders have been added to the file indicating where code should be added, and providing some
hints on what to look for.

The initial version of the Workshop pipeline simply prints it's input as output, you can test that by running
`bin/runworkshop.sh` from the repository root.

* Update `ExtractWords` to split the input strings and output individual words all lowercase. For simplicity don't worry about trimming punctuation, but whitespace should be trimmed and no zero length strings should be emitted.
* Use a counting transform to count occurences of each word
* Create a new DoFn to convert the word/count key-value pairs into strings for output
* Write the output to stdout using the PrintOutput transform which is supplied.
* Optionally, calculate the mean number of occurences using the key-value collection created by the count transform in an earlier step, and include that with the output.

### Testing your pipeline

You can execute `bin/runworkshop.sh` to test your pipeline. This is a script the provides the required
options to `bin/m` to execute the Workshop pipeline in the docker container.

### Tips

* Checkout the [Beam SDK documentation](https://beam.apache.org/releases/javadoc/2.8.0/)
* The [HTTPRequest](https://github.com/mozilla-services/foxsec-pipeline/blob/master/src/main/java/com/mozilla/secops/httprequest/HTTPRequest.java) pipeline does some element counts and mean calculation and may be useful for review
* The imports in the template Workshop class are limited to what it currently uses, so additional imports will be needed as code is added
* There are some other word count examples around
