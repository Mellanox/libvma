# Contributing to libvma

As a contributor, here are the guidelines we would like you to follow:

 - [Submission Guidelines](#submit)
 - [Commit Message Guidelines](#commit)
 - [Coding Rules](#rules)
 - [Unit tests](#tests)
 - [Continuous Integration](#ci)


## <a name="submit"></a> Submission Guidelines


### Submitting an Issue

Before you submit an issue, please search the issue list, to understand if an issue for your problem already exists.


Please describe configuration details where issue is appeared.

A minimal reproduction step by step instruction allows us to quickly confirm a bug.


### Submitting a Pull Request

Before you submit your Pull Request (PR) consider the following guidelines:

1. Fork the `mellanox/libvma` repo.
2. Make your changes in a new git branch:
     ```shell
     git checkout -b fix-branch master
     ```
3. Do relevant modifications and include appropriate unit-test cases.
4. Follow our [Coding Rules](#rules).
5. Run the existing test suite as described in the [Test suite](#tests), and ensure that all tests pass.
6. Prepare sequence of small commits that as one self-contained change. Read [Why Write Small Commit](#patch).
7. Commit your changes using a descriptive commit message that follows our [Commit Message Conventions](#commit).
     ```shell
     git commit -a -s
     ```
8. Once you have committed your changes, it is a good idea to use `git rebase`
   (not `git merge`) to synchronize your work with the main repository.

     ```shell
     git fetch upstream
     git rebase upstream/master
     ```

   This ensures that your working branch has the latest changes from master.
9. Push your branch to GitHub:
    ```shell
    git push origin fix-branch
    ```
10. From within GitHub, open a new pull request that will present you with a [pull request template form](../.github/PULL_REQUEST_TEMPLATE.md)
    that should be filled out. Select `master` as a base for pull request.
    Feel free to post a comment in the pull request to ping reviewers if you are
    awaiting an answer on something.
11. Whenever a maintainer reviews a pull request they may request changes.
    These may be small, such as fixing a typo, or may involve substantive changes.
    Address review feedback as described at [Reviewing a Pull Request](#review).
12. Every pull request is tested on the [Continuous Integration (CI) system](#ci) to
    confirm that it works supported platforms. Ideally, the pull request will pass ("be green") on all of CI's platforms.
    This means that all tests pass and there are no errors.
13. Ask verification after passing continuous integration and getting review approval.
14. Rebase your pull request on top of `master`.
15. Pull request is moved to `vNext` by authority person.
16. Update pull request in case regression report any issues related one.

### Reviewing a Pull Request

In doing a code review, you should make sure that:

* The code is well-designed.
* The functionality is good for the users of the code.
* Any parallel programming is done safely.
* The code isn't more complex than it needs to be.
* The developer isn't implementing things they might need in the future but don't know they need now.
* Code has appropriate unit tests.
* Tests are well-designed.
* The developer used clear names for everything.
* Comments are clear and useful, and mostly explain why instead of what.
* Code is appropriately documented.
* The code conforms to our style guides.

Refer to good practices article from [Google](https://google.github.io/eng-practices/review/reviewer/standard.html).


### <a name="patch"></a> Why Write Small Commit?

It is recommended to keep your changes grouped logically within individual commits. There is no limit to the number of commits in a pull request.

* Reviewed more quickly. It's easier for a reviewer to find five minutes several times to review small patches than to set aside a 30 minute block to review one large patch.
* Reviewed more thoroughly. With large changes, reviewers and authors tend to get frustrated by large volumes of detailed commentary shifting back and forth - sometimes to the point where important points get missed or dropped.
* Less likely to introduce bugs. Since you're making fewer changes, it's easier for you and your reviewer to reason effectively about the impact of the patch and see if a bug has been introduced.
* Less wasted work if they are rejected. If you write a huge patch and then your reviewer says that the overall direction is wrong, you've wasted a lot of work.
* Easier to merge. Working on a large patch takes a long time, so you will have lots of conflicts when you merge, and you will have to merge frequently.
* Easier to design well. It's a lot easier to polish the design and code health of a small change than it is to refine all the details of a large change.
* Less blocking on reviews. Sending self-contained portions of your overall change allows you to continue coding while you wait for your current patch in review.
* Simpler to roll back. A large patch will more likely touch files that get updated between the initial patch submission and a rollback patch, complicating the rollback (the intermediate patches will probably need to be rolled back too).

Refer to good practices article from [Google](https://google.github.io/eng-practices/review/developer/small-cls.html).

### <a name="commit"></a> Commit Message Format

A good commit message should describe what changed and why. There are following rules for commit message format.

Each commit message consists of a **header**, a **body**, and a **footer** separated by blank line.

The `header` is mandatory and must conform to the [Commit Message Header](#commit-header) format.

The `body` is mandatory for fixes and features and must conform to the [Commit Message Body](#commit-body) format.

The `footer` is optional. See [Commit Message Footer](#commit-footer) format.

Any line of the commit message cannot be longer than 100 characters.


#### <a name="commit-header"></a>Commit Message Header

```
issue: <number> <short summary>
```

#### <a name="commit-body"></a>Commit Message Body

Message body must explain the motivation for the change. This commit message should explain **WHY** you are making the change.


#### <a name="commit-footer"></a>Commit Message Footer

The footer can contain information about contributors and reviewers.

`Signed-off-by: name <email>` certifies that you wrote it or otherwise have the right to pass it on as a open-source patch.

`Reviewed-by: name <email>` reviewer completely satisfied that the patch is ready for application.


## <a name="rules"></a> Coding Rules
Keep these rules in mind as you are working:

* All features or bug fixes **must be tested** by unit-tests.
* All public API methods **must be documented**.
* Code should follow [coding style guide](./coding-style.md).


## <a name="tests"></a> Unit tests
This set of tests is based on [Google Test C++] (https://github.com/google/googletest) environment 

Suite support [TAP protocol](https://en.wikipedia.org/wiki/Test_Anything_Protocol) for test result output.
Just set **GTEST_TAP=2** as  environment variable.

This suite includes standard socket api and library specific api tests.
**LD_PRELOAD** should be done to verify target library. 

Build standard tests:
```shell
$ make -C tests/gtest
```

Build specific tests:
```shell
$ make -C tests/gtest CPPFLAGS="-DEXTRA_API_ENABLED=1"
```

Display help:
```shell
$ ./tests/gtest --help
```

All tests can be launched on single node that has two interfaces.

Run tests under OS:
```shell
$ ./tests/gtest --addr=1.1.3.6:1.1.4.6
```
or
```shell
$ ./tests/gtest --if=ens2f0:ens2f1 --gtest_filter=tcp_sendfile.*
```

Run tests under VMA:
```shell
$ LD_PRELOAD=libvma.so ./tests/gtest --addr=1.1.3.6:1.1.4.6
```
or
```shell
$ LD_PRELOAD=libvma.so ./tests/gtest --if=ens2f0:ens2f1 --gtest_filter=tcp_sendfile.*
```


## <a name="ci"></a> Continuous Integration
The project uses Jenkins as a popular open source tool to perform continuous integration and build automation.  
The [Continuous Integration (CI)](../.ci/README.md) scripts are located in [.ci](../.ci) folder.
Jenkins behavior can be controlled by job_matrix.yaml file which has similar syntax/approach as Github actions.

Some verification can be done locally. 
```shell
$ env WORKSPACE=<srcdir> TARGET=[default|extra] jenkins_test_build=yes <srcdir>/contrib/test_jenkins.sh
```

Specific options can be selected from following list:
* jenkins_test_build=[yes|no]
* jenkins_test_compiler=[yes|no]
* jenkins_test_rpm=[yes|no]
* jenkins_test_cov=[yes|no]
* jenkins_test_cppcheck=[yes|no]
* jenkins_test_csbuild=[yes|no]
* jenkins_test_vg=[yes|no]
* jenkins_test_style=[yes|no]
* jenkins_test_gtest=[yes|no]
* jenkins_test_tool=[yes|no]
* jenkins_test_commit=[yes|no]

Results are stored at $WORKSPACE/jenkins folder
