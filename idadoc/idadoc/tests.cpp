#include <cppunit/BriefTestProgressListener.h>
#include <cppunit/CompilerOutputter.h>
#include <cppunit/extensions/TestFactoryRegistry.h>
#include <cppunit/TestResult.h>
#include <cppunit/TestResultCollector.h>
#include <cppunit/extensions/HelperMacros.h>

class MzHeaderTest: public CppUnit::TestFixture
{
	public:
		void setUp(void) {}
		void tearDown(void) {}

	public:
		void foo() {int x; CPPUNIT_ASSERT(x == 3);}
};

//CPPUNIT_TEST_SUITE_REGISTRATION(MzHeaderTest);

bool tests()
{
	CPPUNIT_NS::TestResult controller;
	
	CPPUNIT_NS::TestResultCollector result;
	controller.addListener( &result );  
	
  	CppUnit::TestSuite suite;

	suite.addTest( new CppUnit::TestCaller<MzHeaderTest>(
                       "Load MZ header", 
                       &MzHeaderTest::foo ) );

	return true;
}