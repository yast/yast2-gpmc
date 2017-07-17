#!/usr/bin/env python

from ycp import *
import gettext
from gettext import textdomain
textdomain('mysql')

import_module('Progress')
import_module('Report')
import_module('Message')
import_module('Wizard')


import time
from ycp import *

def Read():

    	#/* GPMC read dialog caption */
    	caption = 'Initializing the GPMC Configuration'

    	steps = 2

    	Progress.New( caption, ' ', steps, [
		'Read the current GPMC configuration',
		'Read the current GPMC state'
	  ], [

		"Reading the current GPMC configuration...",

	    	"Reading the current GPMC state...",

	    	Message.Finished()
	  ],
	  ''
    	)

    	if False: 
	    return False
    	Progress.NextStage()
    	#/* Error message */
    	if False: 
	    Report.Error(Message.CannotReadCurrentSettings())
    	time.sleep(1)

    	if False: 
	    return False
    
    	Progress.NextStep()
    	#/* Error message */
    	if False:
	     Report.Error('Cannot read the current GPMC state.')
    	time.sleep(1)

    	if False: 
	    return False
    
    	Progress.NextStage ()
    	time.sleep(1)
   
    	return True



def Write() :
    	#/* GPMC read dialog caption */
    	caption = 'Saving the GPMC Configuration'

    	steps = 2
    
    	Progress.New(caption, ' ', steps, [
	    	#/* Progress stage 1/2 */
	    	'Write the GPMC settings',
	    	#/* Progress stage 2/2 */
	    	'Adjust the GPMC service'
	   ], [
	    	#/* Progress step 1/2 */
	    	'Writing the GPMC settings...',
	    	#/* Progress step 2/2 */
	    	'Adjusting the GPMC service...',
	    	Message.Finished()	
	   ],
	   ''
    	)

    	time.sleep(1)

    	if False: 
		return False
    	Progress.NextStage()
    	#/* Error message */
    	if False: 
		Report.Error ('Cannot write the GPMC settings.')
    	time.sleep(1)

    	if False: 
		return False
    	Progress.NextStage ()
    	#/* Error message */
    	if False: 
		Report.Error (Message.CannotAdjustService('gpmc'))
    	time.sleep(1)

    	Progress.NextStage ()
    	time.sleep(1)

    	return True


def ReadDialog():
	ret = Read()
	if ret:
		return Symbol('next')
	else:
		return Symbol('abort')


def WriteDialog() :
	ret = Write()
	if ret:
		return Symbol('next')
	else:
		return Symbol('abort')

