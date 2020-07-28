/** NexusOS: regression testing 
 
    Unittests are simple functions that return a binary result.

    ## registration
      Unittests are run early, so registration is a compile-time action.
      In kernel/nexus/test.c, add an entry in unittests that points to your
      function.

    ## early vs. late execution
      Ideally, the execute all paths (good and bad!) in a block of code that 
      is fully isolated from the rest of the system. In practice, this is rare.
      For this reason the test environments support execution at two moments:
      Isolated tests are executed as soon as the screen can show results. 
      Others are executed just before the kernel shell comes up. 

    ## disabling code during tests
      To create isolated tests, you may need to disable some function calls
      into third-party modules. You can test the value of unittest_active and
      unittest_active_early for this. It is possible to run your test both
      early and late, where the early test disables some code using 

      	  if (unittest_active_early)

      that the second tests includes. The unittest for ipc ports demonstrates
      this.
 
 */

#ifndef NEXUS_KERNEL_TEST_H
#define NEXUS_KERNEL_TEST_H

/** enabled during testing, disabled otherwise 
 
    test against this value to disable the parts of your code
    that are call outside the unit we're testing and are therefore
    out of scope */
extern int unittest_active;

/** disable code that cannot run during the early tests, 
    because it relies on a fully initialized system */
extern int unittest_active_early;

/** unittest function template. 
    @return 0 on success, all others denote failure */
typedef int (*unittest_func)(void);

/** run tests that do not need an initialized system */
void unittest_runall_early(void);

/** run tests that need an initialized system */
void unittest_runall_late(void);

/** Execute all *.test files in the initrd file. */
void unittest_runall_user(void);

#endif /* NEXUS_KERNEL_TEST_H */

