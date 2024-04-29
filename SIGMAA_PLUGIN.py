import subprocess
import inspect
import os
import csv
import threading

from java.io import File
from java.util.logging import Level
from org.sleuthkit.autopsy.casemodule.services import Blackboard
from org.sleuthkit.datamodel import BlackboardAttribute
from org.sleuthkit.autopsy.ingest import IngestModule
from org.sleuthkit.autopsy.ingest.IngestModule import IngestModuleException
from org.sleuthkit.autopsy.ingest import DataSourceIngestModule
from org.sleuthkit.autopsy.ingest import IngestModuleFactoryAdapter
from org.sleuthkit.autopsy.ingest import IngestMessage
from org.sleuthkit.autopsy.ingest import IngestServices
from org.sleuthkit.autopsy.coreutils import Logger
from org.sleuthkit.autopsy.casemodule import Case
from org.sleuthkit.autopsy.coreutils import PlatformUtil
from org.sleuthkit.autopsy.datamodel import ContentUtils
from org.sleuthkit.autopsy.casemodule.services import Blackboard


# Factory that defines the name and details of the module and allows Autopsy to create instances of the modules that will do the anlaysis.
class SIGMAAAnalysisIngestModuleFactory(IngestModuleFactoryAdapter):

    def __init__(self):
        self.settings = None
    
    moduleName = "SIGMAA"

    def getModuleDisplayName(self):
        return self.moduleName

    def getModuleDescription(self):
        return "Detection of IOCs in EVTX for Windows and Auditd for Linux Logs"

    def getModuleVersionNumber(self):
        return "1.0"
    
    # True - Module wants to get called for each file
    def isDataSourceIngestModuleFactory(self):
        return True

    # Can return null if isFileIngestModuleFactory returns false
    def createDataSourceIngestModule(self, ingestOptions):
        return SIGMAAAnalysisIngestModule()


# File-level ingest module. One gets created per thread.
# Looks at the attributes of the passed in file.
class SIGMAAAnalysisIngestModule(DataSourceIngestModule):

    _logger = Logger.getLogger(SIGMAAAnalysisIngestModuleFactory.moduleName)

    # Logs a message using a logger object (self._logger) at a specified logging level
    def log(self, level, msg):
        self._logger.logp(level, self.__class__.__name__, inspect.stack()[1][3], msg)
    
    def __init__(self):
        self.context = None

    # Where any setup and configuration is done
    # 'context' is an instance of org.sleuthkit.autopsy.ingest.IngestJobContext.
    # See: http://sleuthkit.org/autopsy/docs/api-docs/3.1/classorg_1_1sleuthkit_1_1autopsy_1_1ingest_1_1_ingest_job_context.html
    def startUp(self, context):
        self.context = context
            
        # Check if platform is windows and set the exe path and rule path
        if PlatformUtil.isWindowsOS():
            # Packager (nuitka) does not like Zircolite being run in from another directory, hence it has to be in the same directory as the plugin
            self.path_to_exe = os.path.join(os.path.dirname(os.path.abspath(__file__)), "zircolite_win_x64_2.20.0.exe")
            # self.path_to_exe = "zircolite_win_x64_2.20.0.exe"
            if not os.path.exists(self.path_to_exe): raise IngestModuleException("Windows EXE File does not exist")
            # TODO: Change this to user input (1 file OR 1 folder)
            self.path_to_evtx_rulefile = os.path.join(os.path.dirname(os.path.abspath(__file__)), "EvtxRule")
            self.path_to_auditd_rulefile = os.path.join(os.path.dirname(os.path.abspath(__file__)), "AuditdRule")
            self.path_to_zircolite_config = os.path.join(os.path.dirname(os.path.abspath(__file__)), "config\\fieldMappings.json")
            self.path_to_evtxdump_bin = os.path.join(os.path.dirname(os.path.abspath(__file__)), "bin\\evtx_dump_win.exe")

            self.log(Level.INFO, "Path to EXE is set to " + str(self.path_to_exe))
            self.log(Level.INFO, "Path to EVTX Rule Folder/File is set to " + str(self.path_to_evtx_rulefile))
            self.log(Level.INFO, "Path to Auditd Rule Folder/File is set to " + str(self.path_to_auditd_rulefile))
        pass

    # Where the analysis is done. Each file will be passed into here.
    # The 'file' object being passed in is of type org.sleuthkit.datamodel.AbstractFile.
    # See: http://www.sleuthkit.org/sleuthkit/docs/jni-docs/classorg_1_1sleuthkit_1_1datamodel_1_1_abstract_file.html
    def process(self, dataSource, progressBar):
        # Retrieve blackboard
        bboard = Case.getCurrentCase().getSleuthkitCase().getBlackboard()
        # Create all of the necessary artifacts with the relevant strings and its value type
        # The string at the end is the UI column for the artifacts
        
        # Group of EVTX artifacts under "Data artifacts"
        try:
            self.log(Level.INFO, "Creation of New Artifacts")
            artID_ioc_evtx = bboard.getOrAddArtifactType("IOC_EVTX_LOGS", "SIGMA Rule Matches in Windows Event Logs")
        except:	self.log(Level.SEVERE, "Error in Artifacts Creation, some artifacts may be missing.")

        # Group of Auditd artifacts under "Data artifacts"
        try:
            self.log(Level.INFO, "Creation of New Artifacts")
            artID_ioc_auditd = bboard.getOrAddArtifactType("IOC_AUDITD_LOGS", "SIGMA Rule Matches in Linux Auditd Logs")
        except:	self.log(Level.SEVERE, "Error in Artifacts Creation, some artifacts may be missing.") 

        # Group of Rule Levels under "Data artifacts"
        try:
            self.log(Level.INFO, "Creation of New Artifacts")
            artID_sigma_info = bboard.getOrAddArtifactType("SIGMA_INFORMATIONAL", "SIGMA Rule Level: Informational")
        except:	self.log(Level.SEVERE, "Error in Artifacts Creation, some artifacts may be missing.")

        try:
            self.log(Level.INFO, "Creation of New Artifacts")
            artID_sigma_low = bboard.getOrAddArtifactType("SIGMA_LOW", "SIGMA Rule Level: Low")
        except:	self.log(Level.SEVERE, "Error in Artifacts Creation, some artifacts may be missing.")

        try:
            self.log(Level.INFO, "Creation of New Artifacts")
            artID_sigma_medium = bboard.getOrAddArtifactType("SIGMA_MEDIUM", "SIGMA Rule Level: Medium")
        except:	self.log(Level.SEVERE, "Error in Artifacts Creation, some artifacts may be missing.")

        try:
            self.log(Level.INFO, "Creation of New Artifacts")
            artID_sigma_high = bboard.getOrAddArtifactType("SIGMA_HIGH", "SIGMA Rule Level: High")
        except:	self.log(Level.SEVERE, "Error in Artifacts Creation, some artifacts may be missing.")

        try:
            self.log(Level.INFO, "Creation of New Artifacts")
            artID_sigma_crit = bboard.getOrAddArtifactType("SIGMA_CRITICAL", "SIGMA Rule Level: Critical")
        except:	self.log(Level.SEVERE, "Error in Artifacts Creation, some artifacts may be missing.")

################################################################################################################################################################################

        ### GENERAL ###

        try: attID_evt_rn = bboard.getOrAddAttributeType("TSK_EVT_RULE_NAME", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "SIGMA Rule Name")
        except: self.log(Level.SEVERE, "== Error in Attributes Creation - SIGMA Rule Name == ")
       
        try: attID_evt_rd = bboard.getOrAddAttributeType("TSK_EVT_RULE_DESCRIPTION", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "SIGMA Rule Description")
        except: self.log(Level.SEVERE, "== Error in Attributes Creation - SIGMA Rule Description == ")
        
        try: attID_evt_rl = bboard.getOrAddAttributeType("TSK_EVT_RULE_LEVEL", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Rule Level")
        except: self.log(Level.SEVERE, "== Error in Attributes Creation - Rule Level == ")

        try: attID_evt_rc = bboard.getOrAddAttributeType("TSK_EVT_RULE_COUNT", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Rule Count")
        except: self.log(Level.SEVERE, "== Error in Attributes Creation - Rule Count == ")

        try: attID_evt_agg = bboard.getOrAddAttributeType("TSK_EVT_AGG", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Agg")
        except: self.log(Level.SEVERE, "== Error in Attributes Creation - Agg == ")    

        try: attID_evt_rid = bboard.getOrAddAttributeType("TSK_EVT_ROW_ID", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Row ID")
        except: self.log(Level.SEVERE, "== Error in Attributes Creation - Row ID == ")

        try: attID_evt_olf = bboard.getOrAddAttributeType("TSK_EVT_ORIGINAL_LOG_FILE", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Orginal Log File")
        except: self.log(Level.SEVERE, "== Error in Attributes Creation - Orginal Log File == ")


        ### EVTX SPECIFIC ###

        try: attID_evtx_mn = bboard.getOrAddAttributeType("TSK_EVTX_MESSAGE_NUMBER", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Message Number")
        except: self.log(Level.SEVERE, "== Error in Attributes Creation - Message Number == ")

        try: attID_evtx_mt = bboard.getOrAddAttributeType("TSK_EVTX_MESSAGE_TOTAL", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Message Total")
        except: self.log(Level.SEVERE, "== Error in Attributes Creation - Message Total == ")

        try: attID_evtx_sbid = bboard.getOrAddAttributeType("TSK_EVTX_SCRIPT_BLOCK_ID", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Script Block ID")
        except: self.log(Level.SEVERE, "== Error in Attributes Creation - Script Block ID == ")

        try: attID_evtx_sbt = bboard.getOrAddAttributeType("TSK_EVTX_SCRIPT_BLOCK_TEXT", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Script Block Text")
        except: self.log(Level.SEVERE, "== Error in Attributes Creation - Script Block Text == ")

        try: attID_evtx_channel = bboard.getOrAddAttributeType("TSK_EVTX_CHANNEL", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Channel")
        except: self.log(Level.SEVERE, "== Error in Attributes Creation - Event Channel == ")
        
        try: attID_evtx_cn = bboard.getOrAddAttributeType("TSK_EVTX_COMPUTER_NAME", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Computer Name")
        except:	self.log(Level.SEVERE, "== Error in Attributes Creation - Computer Name == ")

        try: attID_evtx_aid = bboard.getOrAddAttributeType("TSK_EVTX_ACTIVITY_ID", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Activity ID")
        except:	self.log(Level.SEVERE, "== Error in Attributes Creation - Event Log Activity ID == ")
        
        try: attID_evtx_eid = bboard.getOrAddAttributeType("TSK_EVTX_EVENT_ID", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Event ID")
        except:	self.log(Level.SEVERE, "== Error in Attributes Creation - Event Log Event ID == ")

        try: attID_evtx_erid = bboard.getOrAddAttributeType("TSK_EVTX_EVENT_RECORD_ID", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Event Record ID")
        except:	self.log(Level.SEVERE, "== Error in Attributes Creation - Event Log Event Record ID == ")
        
        try: attID_evtx_pid = bboard.getOrAddAttributeType("TSK_EVTX_PROCESS_ID", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Process ID")
        except:	self.log(Level.SEVERE, "== Error in Attributes Creation - Event Log Process ID == ")

        try: attID_evtx_tid = bboard.getOrAddAttributeType("TSK_EVTX_THREAD_ID", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Thread ID")
        except:	self.log(Level.SEVERE, "== Error in Attributes Creation - Event Log Thread ID == ")
        
        try: attID_evtx_guid = bboard.getOrAddAttributeType("TSK_EVTX_GUID", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "GUID")
        except: self.log(Level.SEVERE, "== Error in Attributes Creation - Event GUID == ")

        try: attID_evtx_pn = bboard.getOrAddAttributeType("TSK_EVTX_PROVIDER_NAME", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Provider Name")
        except: self.log(Level.SEVERE, "== Error in Attributes Creation - Provider Name == ")

        try: attID_evtx_keywords = bboard.getOrAddAttributeType("TSK_EVTX_KEYWORDS", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Keywords")
        except: self.log(Level.SEVERE, "== Error in Attributes Creation - Keywords == ")

        try: attID_evtx_level = bboard.getOrAddAttributeType("TSK_EVTX_LEVEL", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Level")
        except: self.log(Level.SEVERE, "== Error in Attributes Creation - Level == ")

        try: attID_evtx_opcode = bboard.getOrAddAttributeType("TSK_EVTX_OPCODE", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Opcode")
        except: self.log(Level.SEVERE, "== Error in Attributes Creation - Opcode == ")

        try: attID_evtx_uid = bboard.getOrAddAttributeType("TSK_EVTX_USER_ID", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "User ID")
        except: self.log(Level.SEVERE, "== Error in Attributes Creation - User ID == ")

        try: attID_evtx_task = bboard.getOrAddAttributeType("TSK_EVTX_TASK", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Task")
        except: self.log(Level.SEVERE, "== Error in Attributes Creation - Task == ")

        try: attID_evtx_st = bboard.getOrAddAttributeType("TSK_EVTX_SYSTEM_TIME", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "System Time")
        except:	self.log(Level.SEVERE, "== Error in Attributes Creation - System Time == ")
        
        try: attID_evtx_ver = bboard.getOrAddAttributeType("TSK_EVTX_VERSION", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Version")
        except:	self.log(Level.SEVERE, "== Error in Attributes Creation - Version == ")
        
        try: attID_evtx_cmd = bboard.getOrAddAttributeType("TSK_EVTX_COMMAND_LINE", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Command Line")
        except: self.log(Level.SEVERE, "== Error in Attributes Creation - Command Line == ")

        try: attID_evtx_company = bboard.getOrAddAttributeType("TSK_EVTX_COMPANY", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Company")
        except: self.log(Level.SEVERE, "== Error in Attributes Creation - Company == ")

        try: attID_evtx_cd = bboard.getOrAddAttributeType("TSK_EVTX_CURRENT_DIRECTORY", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Current Directory")
        except: self.log(Level.SEVERE, "== Error in Attributes Creation - Current Directory == ")

        try: attID_evtx_desc = bboard.getOrAddAttributeType("TSK_EVTX_DESCRIPTION", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Description")
        except: self.log(Level.SEVERE, "== Error in Attributes Creation - Description == ")

        try: attID_evtx_fv = bboard.getOrAddAttributeType("TSK_EVTX_FILE_VERSION", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "File Version")
        except: self.log(Level.SEVERE, "== Error in Attributes Creation - File Version == ")

        try: attID_evtx_sha1 = bboard.getOrAddAttributeType("TSK_EVTX_SHA1", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "SHA1 Hash")
        except: self.log(Level.SEVERE, "== Error in Attributes Creation - SHA1 Hash == ")

        try: attID_evtx_md5 = bboard.getOrAddAttributeType("TSK_EVTX_MD5", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "MD5 Hash")
        except: self.log(Level.SEVERE, "== Error in Attributes Creation - MD5 Hash == ")

        try: attID_evtx_sha256 = bboard.getOrAddAttributeType("TSK_EVTX_SHA256", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "SHA256 Hash")
        except: self.log(Level.SEVERE, "== Error in Attributes Creation - SHA256 Hash == ")

        try: attID_evtx_imphash = bboard.getOrAddAttributeType("TSK_EVTX_IMPHASH", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "IMPHASH")
        except: self.log(Level.SEVERE, "== Error in Attributes Creation - IMPHASH == ")

        try: attID_evtx_hash = bboard.getOrAddAttributeType("TSK_EVTX_HASHES", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Hashes")
        except: self.log(Level.SEVERE, "== Error in Attributes Creation - Hashes == ")

        try: attID_evtx_img = bboard.getOrAddAttributeType("TSK_EVTX_IMAGE", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Image")
        except: self.log(Level.SEVERE, "== Error in Attributes Creation - Image == ")

        try: attID_evtx_il = bboard.getOrAddAttributeType("TSK_EVTX_INTEGRITY_LEVEL", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Integrity Level")
        except: self.log(Level.SEVERE, "== Error in Attributes Creation - Integrity Level == ")

        try: attID_evtx_lguid = bboard.getOrAddAttributeType("TSK_EVTX_LOGON_GUID", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Logon GUID")
        except: self.log(Level.SEVERE, "== Error in Attributes Creation - Logon GUID == ")

        try: attID_evtx_lid = bboard.getOrAddAttributeType("TSK_EVTX_LOGON_ID", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Logon ID")
        except: self.log(Level.SEVERE, "== Error in Attributes Creation - Logon ID == ")

        try: attID_evtx_ofn = bboard.getOrAddAttributeType("TSK_EVTX_ORIGINAL_FILENAME", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Original File Name")
        except: self.log(Level.SEVERE, "== Error in Attributes Creation - Original File Name == ")

        try: attID_evtx_pcmd = bboard.getOrAddAttributeType("TSK_EVTX_PARENT_COMMAND_LINE", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Parent Command Line")
        except: self.log(Level.SEVERE, "== Error in Attributes Creation - Parent Command Line == ")

        try: attID_evtx_pimg = bboard.getOrAddAttributeType("TSK_EVTX_PARENT_IMAGE", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Parent Image")
        except: self.log(Level.SEVERE, "== Error in Attributes Creation - Parent Image == ")

        try: attID_evtx_ppguid = bboard.getOrAddAttributeType("TSK_EVTX_PARENT_PROCESS_GUID", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Parent Process GUID")
        except: self.log(Level.SEVERE, "== Error in Attributes Creation - Parent Process GUID == ")

        try: attID_evtx_ppid = bboard.getOrAddAttributeType("TSK_EVTX_PARENT_PROCESS_ID", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Parent Process ID")
        except: self.log(Level.SEVERE, "== Error in Attributes Creation - Parent Process ID == ")

        try: attID_evtx_pguid = bboard.getOrAddAttributeType("TSK_EVTX_PROCESS_GUID", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Process GUID")
        except: self.log(Level.SEVERE, "== Error in Attributes Creation - Process GUID == ")

        try: attID_evtx_product = bboard.getOrAddAttributeType("TSK_EVTX_PRODUCT", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Product")
        except: self.log(Level.SEVERE, "== Error in Attributes Creation - Product == ")

        try: attID_evtx_tsid = bboard.getOrAddAttributeType("TSK_EVTX_TERMINAL_SESSION_ID", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Terminal Session ID")
        except: self.log(Level.SEVERE, "== Error in Attributes Creation - Terminal Session ID == ")

        try: attID_evtx_user = bboard.getOrAddAttributeType("TSK_EVTX_USER", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "User")
        except: self.log(Level.SEVERE, "== Error in Attributes Creation - User == ")

        try: attID_evtx_utc = bboard.getOrAddAttributeType("TSK_EVTX_UTC_TIME", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "UTC Time")
        except: self.log(Level.SEVERE, "== Error in Attributes Creation - UTC Time == ")

        try: attID_evtx_al = bboard.getOrAddAttributeType("TSK_EVTX_ACCESS_LIST", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Access List")
        except: self.log(Level.SEVERE, "== Error in Attributes Creation - Access List == ")

        try: attID_evtx_am = bboard.getOrAddAttributeType("TSK_EVTX_ACCESS_MASK", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Access Mask")
        except: self.log(Level.SEVERE, "== Error in Attributes Creation - Access Mask == ")

        try: attID_evtx_hid = bboard.getOrAddAttributeType("TSK_EVTX_HANDLE_ID", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Handle ID")
        except: self.log(Level.SEVERE, "== Error in Attributes Creation - Handle ID == ")

        try: attID_evtx_on = bboard.getOrAddAttributeType("TSK_EVTX_OBJECT_NAME", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Object Name")
        except: self.log(Level.SEVERE, "== Error in Attributes Creation - Object Name == ")

        try: attID_evtx_os = bboard.getOrAddAttributeType("TSK_EVTX_OBJECT_SERVER", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Object Server")
        except: self.log(Level.SEVERE, "== Error in Attributes Creation - Object Server == ")

        try: attID_evtx_ot = bboard.getOrAddAttributeType("TSK_EVTX_OBJECT_TYPE", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Object Type")
        except: self.log(Level.SEVERE, "== Error in Attributes Creation - Object Type == ")

        try: attID_evtx_pn = bboard.getOrAddAttributeType("TSK_EVTX_PROCESS_NAME", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Process Name")
        except: self.log(Level.SEVERE, "== Error in Attributes Creation - Process Name == ")

        try: attID_evtx_ra = bboard.getOrAddAttributeType("TSK_EVTX_RESOURCE_ATTRIBUTES", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Resource Attributes")
        except: self.log(Level.SEVERE, "== Error in Attributes Creation - Resource Attributes == ")

        try: attID_evtx_sdn = bboard.getOrAddAttributeType("TSK_EVTX_SUBJECT_DOMAIN_NAME", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Subject Domain Name")
        except: self.log(Level.SEVERE, "== Error in Attributes Creation - Subject Domain Name == ")

        try: attID_evtx_slid = bboard.getOrAddAttributeType("TSK_EVTX_SUBJECT_LOGON_ID", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Subject Logon ID")
        except: self.log(Level.SEVERE, "== Error in Attributes Creation - Subject Logon ID == ")

        try: attID_evtx_sun = bboard.getOrAddAttributeType("TSK_EVTX_SUBJECT_USER_NAME", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Subject User Name")
        except: self.log(Level.SEVERE, "== Error in Attributes Creation - Subject User Name == ")

        try: attID_evtx_susid = bboard.getOrAddAttributeType("TSK_EVTX_SUBJECT_USER_SID", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Subject User SID")
        except: self.log(Level.SEVERE, "== Error in Attributes Creation - Subject User SID == ")

        try: attID_evtx_param1 = bboard.getOrAddAttributeType("TSK_EVTX_PARAM1", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Parameter 1")
        except: self.log(Level.SEVERE, "== Error in Attributes Creation - Parameter 1 == ")

        try: attID_evtx_param2 = bboard.getOrAddAttributeType("TSK_EVTX_PARAM2", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Parameter 2")
        except: self.log(Level.SEVERE, "== Error in Attributes Creation - Parameter 2 == ")

        try: attID_evtx_path = bboard.getOrAddAttributeType("TSK_EVTX_PATH", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Path")
        except: self.log(Level.SEVERE, "== Error in Attributes Creation - Path == ")


        ### AUDITD SPECIFIC ###

        try: attID_auditd_type = bboard.getOrAddAttributeType("TSK_AUDITD_TYPE", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Type")
        except: self.log(Level.SEVERE, "== Error in Attributes Creation - Type == ")

        try: attID_auditd_ts = bboard.getOrAddAttributeType("TSK_AUDITD_TIMESTAMP", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Timestamp")
        except: self.log(Level.SEVERE, "== Error in Attributes Creation - Timestamp == ")

        try:attID_auditd_arch = bboard.getOrAddAttributeType("TSK_AUDITD_ARCH", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "CPU Architecture")
        except: self.log(Level.SEVERE, "== Error in Attributes Creation - CPU Architecture == ")

        try: attID_auditd_syscall = bboard.getOrAddAttributeType("TSK_AUDITD_SYSCALL", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "System Call")
        except: self.log(Level.SEVERE, "== Error in Attributes Creation - System Call == ")

        try: attID_auditd_success = bboard.getOrAddAttributeType("TSK_AUDITD_SYSCALL_SUCCESS", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Success")
        except: self.log(Level.SEVERE, "== Error in Attributes Creation - System Call Success == ")

        try: attID_auditd_exit = bboard.getOrAddAttributeType("TSK_AUDITD_EXIT", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Exit Status")
        except: self.log(Level.SEVERE, "== Error in Attributes Creation - Exit Status == ")

        try: attID_auditd_a0 = bboard.getOrAddAttributeType("TSK_AUDITD_A0", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "A0")
        except: self.log(Level.SEVERE, "== Error in Attributes Creation - 1st Argument (a0) == ")

        try: attID_auditd_a1 = bboard.getOrAddAttributeType("TSK_AUDITD_A1", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "A1")
        except: self.log(Level.SEVERE, "== Error in Attributes Creation - 2nd Argument (a1) == ")

        try: attID_auditd_a2 = bboard.getOrAddAttributeType("TSK_AUDITD_A2", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "A2")
        except: self.log(Level.SEVERE, "== Error in Attributes Creation - 3rd Argument (a2) == ")

        try: attID_auditd_a3 = bboard.getOrAddAttributeType("TSK_AUDITD_A3", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "A3")
        except: self.log(Level.SEVERE, "== Error in Attributes Creation - 4th Argument (a3) == ")

        # Number of PATH auxiliary records that follow the syscall record
        try: attID_auditd_items = bboard.getOrAddAttributeType("TSK_AUDITD_ITEMS", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Items")
        except: self.log(Level.SEVERE, "== Error in Attributes Creation - Items == ")

        try: attID_auditd_ppid = bboard.getOrAddAttributeType("TSK_AUDITD_PARENT_PROCESS_ID", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Parent Process ID ")
        except: self.log(Level.SEVERE, "== Error in Attributes Creation - Parent Process ID == ")

        try: attID_auditd_pid = bboard.getOrAddAttributeType("TSK_AUDITD_PROCESS_ID", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Process ID ")
        except: self.log(Level.SEVERE, "== Error in Attributes Creation - Process ID == ")

        try: attID_auditd_auid = bboard.getOrAddAttributeType("TSK_AUDITD_AUDIT_USER_ID", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Audit User ID")
        except: self.log(Level.SEVERE, "== Error in Attributes Creation - Audit User ID == ")

        try: attID_auditd_uid = bboard.getOrAddAttributeType("TSK_AUDITD_USER_ID", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "User ID")
        except: self.log(Level.SEVERE, "== Error in Attributes Creation - User ID == ")

        try: attID_auditd_gid = bboard.getOrAddAttributeType("TSK_AUDITD_GROUP_ID", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Group ID")
        except: self.log(Level.SEVERE, "== Error in Attributes Creation - Group ID == ")

        try: attID_auditd_euid = bboard.getOrAddAttributeType("TSK_AUDITD_EFFECTIVE_USER_ID", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Effective User ID")
        except: self.log(Level.SEVERE, "== Error in Attributes Creation - Effective User ID == ")

        try: attID_auditd_suid = bboard.getOrAddAttributeType("TSK_AUDITD_SET_USER_ID", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Set User ID")
        except: self.log(Level.SEVERE, "== Error in Attributes Creation - Set User ID == ")

        try: attID_auditd_fsuid = bboard.getOrAddAttributeType("TSK_AUDITD_FILE_SYSTEM_USER_ID", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "File System User ID")
        except: self.log(Level.SEVERE, "== Error in Attributes Creation - File System User ID == ")

        try: attID_auditd_egid = bboard.getOrAddAttributeType("TSK_AUDITD_EFFECTIVE_GROUP_ID", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Effective Group ID")
        except: self.log(Level.SEVERE, "== Error in Attributes Creation - Effective Group ID == ")

        try: attID_auditd_sgid = bboard.getOrAddAttributeType("TSK_AUDITD_SET_GROUP_ID", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Set Group ID")
        except: self.log(Level.SEVERE, "== Error in Attributes Creation - Set Group ID == ")

        try: attID_auditd_fsgid = bboard.getOrAddAttributeType("TSK_AUDITD_FILE_SYSTEM_GROUP_ID", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "File System Group ID")
        except: self.log(Level.SEVERE, "== Error in Attributes Creation - File System Group ID == ")

        try: attID_auditd_tty = bboard.getOrAddAttributeType("TSK_AUDITD_TTY", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Invoked Terminal")
        except: self.log(Level.SEVERE, "== Error in Attributes Creation - Invoked Terminal == ")

        try: attID_auditd_ses = bboard.getOrAddAttributeType("TSK_AUDITD_SES", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Session ID")
        except: self.log(Level.SEVERE, "== Error in Attributes Creation - Session ID == ")

        try: attID_auditd_comm = bboard.getOrAddAttributeType("TSK_AUDITD_COMM", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Command")
        except: self.log(Level.SEVERE, "== Error in Attributes Creation - Command == ")

        try: attID_auditd_exe = bboard.getOrAddAttributeType("TSK_AUDITD_EXE", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Executable Path")
        except: self.log(Level.SEVERE, "== Error in Attributes Creation - Executable Path == ")

        # SELinux context with which the analyzed process was labeled at the time of execution
        try: attID_auditd_subj = bboard.getOrAddAttributeType("TSK_AUDITD_SUBJ", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Subject")
        except: self.log(Level.SEVERE, "== Error in Attributes Creation - Subject == ")

        # Administrator-defined string associated with the rule that generated this event
        try: attID_auditd_key = bboard.getOrAddAttributeType("TSK_AUDITD_KEY", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Key")
        except: self.log(Level.SEVERE, "== Error in Attributes Creation - Key == ")

        try: attID_auditd_host = bboard.getOrAddAttributeType("TSK_AUDITD_HOST", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Host")
        except: self.log(Level.SEVERE, "== Error in Attributes Creation - Host == ")

        try: attID_auditd_cwd = bboard.getOrAddAttributeType("TSK_AUDITD_CWD", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Current Working Directory")
        except: self.log(Level.SEVERE, "== Error in Attributes Creation - Current Working Directory == ")

        # Indicates which item, of the total number of items referenced in the SYSCALL type record, the current record is
        # This number is zero-based; a value of 0 means it is the first item
        try: attID_auditd_item = bboard.getOrAddAttributeType("TSK_AUDITD_ITEM", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Item")
        except: self.log(Level.SEVERE, "== Error in Attributes Creation - Item == ")

        # Path of the file or directory that was passed to the system call as an argument
        try: attID_auditd_name = bboard.getOrAddAttributeType("TSK_AUDITD_NAME", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Name")
        except: self.log(Level.SEVERE, "== Error in Attributes Creation - Name == ")

        try: attID_auditd_inode = bboard.getOrAddAttributeType("TSK_AUDITD_INODE", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Inode")
        except: self.log(Level.SEVERE, "== Error in Attributes Creation - Inode == ")

        # Minor and major ID of the device that contains the file or directory recorded in this event
        try: attID_auditd_dev = bboard.getOrAddAttributeType("TSK_AUDITD_DEV", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Device")
        except: self.log(Level.SEVERE, "== Error in Attributes Creation - Device == ")

        # File or directory permissions
        try: attID_auditd_mode = bboard.getOrAddAttributeType("TSK_AUDITD_MODE", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Mode")
        except: self.log(Level.SEVERE, "== Error in Attributes Creation - Mode == ")

        try: attID_auditd_ouid = bboard.getOrAddAttributeType("TSK_AUDITD_OWNER_USER_ID", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Owner User ID")
        except: self.log(Level.SEVERE, "== Error in Attributes Creation - Owner User ID == ")

        try: attID_auditd_ogid = bboard.getOrAddAttributeType("TSK_AUDITD_OWNER_GROUP_ID", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Owner Group ID")
        except: self.log(Level.SEVERE, "== Error in Attributes Creation - Owner Group ID == ")

        # Recorded device identifier for special files only
        try: attID_auditd_rdev = bboard.getOrAddAttributeType("TSK_AUDITD_RDEV", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Recorded Device ID")
        except: self.log(Level.SEVERE, "== Error in Attributes Creation - Recorded Device ID == ")

        # SELinux context with which the recorded file or directory was labeled at the time of execution
        try: attID_auditd_obj = bboard.getOrAddAttributeType("TSK_AUDITD_OBJ", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Object")
        except: self.log(Level.SEVERE, "== Error in Attributes Creation - Object == ")

        # Intent of each path record's operation in the context of a given syscall
        try: attID_auditd_objtype = bboard.getOrAddAttributeType("TSK_AUDITD_OBJ_TYPE", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Object Type")
        except: self.log(Level.SEVERE, "== Error in Attributes Creation - Object Type == ")

        # Setting of a permitted file system-based capability of the file or directory object
        try: attID_auditd_capfp = bboard.getOrAddAttributeType("TSK_AUDITD_CAPFP", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Capability FP")
        except: self.log(Level.SEVERE, "== Error in Attributes Creation - Capability FP == ")

        # Setting of an inherited file system-based capability of the file or directory object
        try: attID_auditd_capfi = bboard.getOrAddAttributeType("TSK_AUDITD_CAPFI", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Capability FI")
        except: self.log(Level.SEVERE, "== Error in Attributes Creation - Capability FI == ")

        # Setting of the effective bit of the file system-based capability of the file or directory object
        try: attID_auditd_capfe = bboard.getOrAddAttributeType("TSK_AUDITD_CAPFE", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Capability Effective Bit")
        except: self.log(Level.SEVERE, "== Error in Attributes Creation - Capability Effective Bit == ")

        # Version of the file system-based capability of the file or directory object
        try: attID_auditd_capfver = bboard.getOrAddAttributeType("TSK_AUDITD_CAPFVER", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "File Capability Version")
        except: self.log(Level.SEVERE, "== Error in Attributes Creation - File Capability Version == ")

        # Full command-line in hex
        try: attID_auditd_proctitle = bboard.getOrAddAttributeType("TSK_AUDITD_PROCTITLE", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Process Title")
        except: self.log(Level.SEVERE, "== Error in Attributes Creation - Process Title == ")

        try: attID_auditd_ver = bboard.getOrAddAttributeType("TSK_AUDITD_VER", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Version")
        except: self.log(Level.SEVERE, "== Error in Attributes Creation - Version == ")

        try: attID_auditd_format = bboard.getOrAddAttributeType("TSK_AUDITD_FORMAT", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Format")
        except: self.log(Level.SEVERE, "== Error in Attributes Creation - Format == ")

        try: attID_auditd_kernel = bboard.getOrAddAttributeType("TSK_AUDITD_KERNEL", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Kernel")
        except: self.log(Level.SEVERE, "== Error in Attributes Creation - Kernel == ")

        try: attID_auditd_res = bboard.getOrAddAttributeType("TSK_AUDITD_RES", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Result")
        except: self.log(Level.SEVERE, "== Error in Attributes Creation - Result == ")

        try: attID_auditd_op = bboard.getOrAddAttributeType("TSK_AUDITD_OP", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Operation")
        except: self.log(Level.SEVERE, "== Error in Attributes Creation - Operation == ")

        try: attID_auditd_acct = bboard.getOrAddAttributeType("TSK_AUDITD_ACCT", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Account")
        except: self.log(Level.SEVERE, "== Error in Attributes Creation - Account == ")

        try: attID_auditd_hostname = bboard.getOrAddAttributeType("TSK_AUDITD_HOSTNAME", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Hostname")
        except: self.log(Level.SEVERE, "== Error in Attributes Creation - Hostname == ")

        try: attID_auditd_addr = bboard.getOrAddAttributeType("TSK_AUDITD_ADDR", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Address")
        except: self.log(Level.SEVERE, "== Error in Attributes Creation - Address == ")

        try: attID_auditd_terminal = bboard.getOrAddAttributeType("TSK_AUDITD_TERMINAL", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Terminal")
        except: self.log(Level.SEVERE, "== Error in Attributes Creation - Terminal == ")

        try: attID_auditd_argc = bboard.getOrAddAttributeType("TSK_AUDITD_ARGC", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Argument Count")
        except: self.log(Level.SEVERE, "== Error in Attributes Creation - Argument Count == ")

################################################################################################################################################################################

        # Find the Log Files
        progressBar.switchToDeterminate(4)

        ## Windows Event Log Files
        evtx_files = []
        fileManager = Case.getCurrentCase().getServices().getFileManager()
        evtx_files = fileManager.findFiles(dataSource, "%.evtx")
        self.log(Level.INFO, "Found " + str(len(evtx_files)) + " Evtx log files")
        evtx_fileCount = 0

        ## Linux Auditd Log Files
        auditd_files = []
        auditd_files = fileManager.findFiles(dataSource, "audit.log") + fileManager.findFiles(dataSource, "audit.log.%")
        self.log(Level.INFO, "Found " + str(len(auditd_files)) + " Auditd log files")
        auditd_fileCount = 0
        
        ########################################################################################################################################################################

        # Create AnalysisResults folder in the temp directory
        progressBar.progress(1)

        tempDir = Case.getCurrentCase().getTempDirectory()
        self.log(Level.INFO, "Create Directory " + tempDir)

        ## Windows Event Log Files
        temp_evtx_dir = os.path.join(tempDir, "EvtxAnalysisResults")
        try: os.mkdir(temp_evtx_dir)
        except: self.log(Level.INFO, "EvtxAnalysisResults Directory already exists " + temp_evtx_dir)
        ## Linux Auditd Log Files
        temp_auditd_dir = os.path.join(tempDir, "AuditdAnalysisResults")
        try: os.mkdir(temp_auditd_dir)
        except: self.log(Level.INFO, "AuditdAnalysisResults Directory already exists " + temp_auditd_dir)

        # So content from previous run won't affect current run
        def delete_directory_contents(directory):
            try:
                lock.acquire()
                # Check if the directory exists
                if os.path.exists(directory) and os.path.isdir(directory):
                    # List all files and directories within the directory
                    for filename in os.listdir(directory):
                        filepath = os.path.join(directory, filename)
                        os.remove(filepath)  # Remove file
                self.log(Level.INFO, "Deleting previously generated directory content for " + directory)

            except: self.log(Level.SEVERE, "Error in deleting previous directory content")
            finally: lock.release()

        # Create a lock object for thread synchronization
        lock = threading.Lock()

        delete_evtx_dir_thread = threading.Thread(target=delete_directory_contents, args=(temp_evtx_dir,))
        delete_auditd_dir_thread = threading.Thread(target=delete_directory_contents, args=(temp_auditd_dir,))
        delete_evtx_dir_thread.start()
        delete_auditd_dir_thread.start()
        delete_evtx_dir_thread.join()  # Wait for the deletion thread to complete before continuing
        delete_auditd_dir_thread.join()

        ########################################################################################################################################################################

        # Write out each Log file to the temp directory
        progressBar.progress(2)
        ## Windows Event Log Files
        for file in evtx_files:
            # Check if the user pressed cancel 
            if self.context.isJobCancelled(): return IngestModule.ProcessResult.OK
            evtx_fileCount += 1
            # Save all the evtx files locally in the temp directory
            ContentUtils.writeToFile(file, File(os.path.join(temp_evtx_dir, file.getName())))
            self.log(Level.INFO, "File " + str(evtx_fileCount) + " - " + file.getName() + " is written to the directory")
        if evtx_fileCount == 0:
            self.log(Level.INFO, "No Evtx log files are found")
        else:
            self.log(Level.INFO, "All Evtx log files written to " + temp_evtx_dir)


        ## Linux Auditd Log Files
        for file in auditd_files:
            # Check if the user pressed cancel 
            if self.context.isJobCancelled(): return IngestModule.ProcessResult.OK
            auditd_fileCount += 1
            # Save all the auditd files locally in the temp directory
            ContentUtils.writeToFile(file, File(os.path.join(temp_auditd_dir, file.getName())))
            self.log(Level.INFO, "File " + str(auditd_fileCount) + " - " + file.getName() + " is written to the directory")
        if auditd_fileCount == 0:
            self.log(Level.INFO, "No Auditd log files are found")
        else:
            self.log(Level.INFO, "All Auditd log files written to " + temp_auditd_dir)

        if (evtx_fileCount == 0) and (auditd_fileCount == 0):
            message = IngestMessage.createMessage(IngestMessage.MessageType.DATA, "SIGMAA", "No supported log files are found")
            IngestServices.getInstance().postMessage(message)
            return IngestModule.ProcessResult.OK

        ########################################################################################################################################################################

        # Run the EXE
        # json file is saved to the temp directory
        progressBar.progress(3)
        
        # If there is a .json rule file, prioritize it and adjust self.path to point to it
        evtx_rulefilelist = os.listdir(self.path_to_evtx_rulefile)
        # Filter the list to get only files ending with ".json"
        evtx_json_files = [file for file in evtx_rulefilelist if file.endswith(".json")]
        if len(evtx_json_files) > 0:
            self.path_to_evtx_rulefile = os.path.join(self.path_to_evtx_rulefile, evtx_json_files[0])

        auditd_rulefilelist = os.listdir(self.path_to_auditd_rulefile)
        # Filter the list to get only files ending with ".json"
        auditd_json_files = [file for file in auditd_rulefilelist if file.endswith(".json")]
        if len(auditd_json_files) > 0:
            self.path_to_auditd_rulefile = os.path.join(self.path_to_auditd_rulefile, auditd_json_files[0])


        # If xxx_results.csv already exists:
        # - Delete it first
        # - Make sure deletion is complete to prevent race condition
        # Define threading locks
        file_deletion_event = threading.Event()

        evtx_csv_file_path = os.path.join(temp_evtx_dir, "evtx_results.csv")
        auditd_csv_file_path = os.path.join(temp_auditd_dir, "auditd_results.csv")

        evtx_command = [self.path_to_exe, "--evtx", str(temp_evtx_dir), 
                   "-r", self.path_to_evtx_rulefile, 
                   "--config", self.path_to_zircolite_config, 
                   "-o", (str(temp_evtx_dir) + "\\evtx_results.csv"),
                   "--evtx_dump", self.path_to_evtxdump_bin,
                   "--csv-output"]
        
        auditd_command = [self.path_to_exe, "--events", str(temp_auditd_dir), 
                   "-r", self.path_to_auditd_rulefile, 
                   "--config", self.path_to_zircolite_config, 
                   "-o", (str(temp_auditd_dir) + "\\auditd_results.csv"),
                   "--auditd",
                   "--csv-output",
                   "-fp", "audit.log*"] # So it runs audit.log.1 too

        def delete_file(csv_file_path):
            # Delete the file if it exists
            if os.path.exists(csv_file_path):
                os.remove(csv_file_path)
                self.log(Level.INFO, "Deleting previously generated csv file: " + csv_file_path)
            # Set the event to indicate file deletion is complete
            file_deletion_event.set()

        def execute_command(command):
            # Wait for file deletion to complete before proceeding
            file_deletion_event.wait()
            # Execute the command and wait for it to complete
            subprocess.Popen(command).wait()

        # Create threads for file deletion and command execution
        evtx_delete_thread = threading.Thread(target=delete_file, args=(evtx_csv_file_path,))
        auditd_delete_thread = threading.Thread(target=delete_file, args=(auditd_csv_file_path,))
        evtx_execute_thread = threading.Thread(target=execute_command, args=(evtx_command,))
        auditd_execute_thread = threading.Thread(target=execute_command, args=(auditd_command,))

        # Start the file deletion threads
        evtx_delete_thread.start()
        auditd_delete_thread.start()

        # Start the command execution threads
        evtx_execute_thread.start()
        auditd_execute_thread.start()

        # Wait for all threads to complete
        evtx_delete_thread.join()
        auditd_delete_thread.join()
        evtx_execute_thread.join()
        auditd_execute_thread.join() 

        # Wait for the csv file to be written
        while "evtx_results.csv" not in os.listdir(temp_evtx_dir):
            self.log(Level.INFO, "Waiting for the Evtx CSV file to be written")
            # Check if the user pressed cancel 
            if self.context.isJobCancelled(): return IngestModule.ProcessResult.OK
        
        while "auditd_results.csv" not in os.listdir(temp_auditd_dir):
            self.log(Level.INFO, "Waiting for the Auditd CSV file to be written")
            # Check if the user pressed cancel 
            if self.context.isJobCancelled(): return IngestModule.ProcessResult.OK
        

        # Check if there is any result of the IOC by checking if xxx_results.csv is empty
        def check_if_file_empty(file_path):
            try:
                with open(file_path, "r") as csv_file:
                    csv_reader = csv.reader(csv_file)
                    next(csv_reader)    # Attempt to read the first row
                    return False        # File is not empty if first row is successfully read
            except StopIteration:
                return True             # File is empty
        
        evtx_csv_path = os.path.join(temp_evtx_dir, "evtx_results.csv")
        auditd_csv_path = os.path.join(temp_auditd_dir, "auditd_results.csv")

        evtx_empty = check_if_file_empty(evtx_csv_path)
        auditd_empty = check_if_file_empty(auditd_csv_path)

        if ((evtx_empty == True) and (auditd_empty == True)):
            message = IngestMessage.createMessage(IngestMessage.MessageType.DATA, "SIGMAA", "No IOCs are found")
            IngestServices.getInstance().postMessage(message)
            return IngestModule.ProcessResult.OK
           
        ########################################################################################################################################################################

        # Create an artifact on the blackboard
        progressBar.progress(4)

        ## Windows Event Log Files
        if evtx_empty == False:
            # Read each line of the CSV file using DictReader
            for row in csv.DictReader(open(str(evtx_csv_file_path)), delimiter=';'):
                try:
                    for file in evtx_files:
                        # Find the index of the last occurrence of '.evtx' in both strings
                        # Can't use index till "-" method like auditd since you can name your evtx differently (with "-")
                        index1 = file.getName().rfind('.evtx')
                        index2 = str(row["OriginalLogfile"]).rfind('.evtx')

                        # Extract the substrings up to '.evtx' (including '.evtx' itself)
                        filename1 = file.getName()[:index1 + 5]
                        filename2 = str(row["OriginalLogfile"])[:index2 + 5]

                        # Check the file name and create and attach the artifact to the file (Summary + Rule Level)
                        if (filename1 == filename2):           
                            # Summary
                            evtx_art = file.newArtifact(artID_ioc_evtx.getTypeID())

                            # Rule Level
                            rule_level = str(row["rule_level"])

                            if rule_level == "informational":
                                art_i = file.newArtifact(artID_sigma_info.getTypeID())
                                # Add attributes to the artifact
                                self.log(Level.INFO, "Adding new Informational Level SIGMA Rule Artifact")
                                art_i.addAttributes(((BlackboardAttribute(attID_evt_rn, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["rule_title"]))), \
                                                    (BlackboardAttribute(attID_evt_rd, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["rule_description"]))), \
                                                    (BlackboardAttribute(attID_evt_rl, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["rule_level"]))), \
                                                    (BlackboardAttribute(attID_evt_rc, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["rule_count"]))), \
                                                    (BlackboardAttribute(attID_evt_agg, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["agg"]))), \
                                                    (BlackboardAttribute(attID_evt_rid, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["row_id"]))), \
                                                    (BlackboardAttribute(attID_evt_olf, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["OriginalLogfile"]))), \
                                                    (BlackboardAttribute(attID_evtx_mn, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["MessageNumber"]))), \
                                                    (BlackboardAttribute(attID_evtx_mt, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["MessageTotal"]))), \
                                                    (BlackboardAttribute(attID_evtx_sbid, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["ScriptBlockId"]))), \
                                                    (BlackboardAttribute(attID_evtx_sbt, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["ScriptBlockText"]))), \
                                                    (BlackboardAttribute(attID_evtx_channel, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["Channel"]))), \
                                                    (BlackboardAttribute(attID_evtx_cn, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["Computer"]))), \
                                                    (BlackboardAttribute(attID_evtx_aid, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["ActivityID"]))), \
                                                    (BlackboardAttribute(attID_evtx_eid, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["EventID"]))), \
                                                    (BlackboardAttribute(attID_evtx_erid, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["EventRecordID"]))), \
                                                    (BlackboardAttribute(attID_evtx_pid, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["ProcessID"]))), \
                                                    (BlackboardAttribute(attID_evtx_tid, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["ThreadID"]))), \
                                                    (BlackboardAttribute(attID_evtx_keywords, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["Keywords"]))), \
                                                    (BlackboardAttribute(attID_evtx_level, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["Level"]))), \
                                                    (BlackboardAttribute(attID_evtx_opcode, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["Opcode"]))), \
                                                    (BlackboardAttribute(attID_evtx_guid, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["Guid"]))), \
                                                    (BlackboardAttribute(attID_evtx_pn, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["Provider_Name"]))), \
                                                    (BlackboardAttribute(attID_evtx_uid, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["UserID"]))), \
                                                    (BlackboardAttribute(attID_evtx_task, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["Task"]))), \
                                                    (BlackboardAttribute(attID_evtx_st, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["SystemTime"]))), \
                                                    (BlackboardAttribute(attID_evtx_ver, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["Version"]))), \
                                                    (BlackboardAttribute(attID_evtx_cmd, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["CommandLine"]))), \
                                                    (BlackboardAttribute(attID_evtx_company, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["Company"]))), \
                                                    (BlackboardAttribute(attID_evtx_cd, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["CurrentDirectory"]))), \
                                                    (BlackboardAttribute(attID_evtx_desc, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["Description"]))), \
                                                    (BlackboardAttribute(attID_evtx_fv, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["FileVersion"]))), \
                                                    (BlackboardAttribute(attID_evtx_sha1, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["SHA1"]))), \
                                                    (BlackboardAttribute(attID_evtx_md5, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["MD5"]))), \
                                                    (BlackboardAttribute(attID_evtx_sha256, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["SHA256"]))), \
                                                    (BlackboardAttribute(attID_evtx_imphash, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["IMPHASH"]))), \
                                                    (BlackboardAttribute(attID_evtx_hash, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["Hashes"]))), \
                                                    (BlackboardAttribute(attID_evtx_img, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["Image"]))), \
                                                    (BlackboardAttribute(attID_evtx_il, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["IntegrityLevel"]))), \
                                                    (BlackboardAttribute(attID_evtx_lguid, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["LogonGuid"]))), \
                                                    (BlackboardAttribute(attID_evtx_lid, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["LogonId"]))), \
                                                    (BlackboardAttribute(attID_evtx_ofn, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["OriginalFileName"]))), \
                                                    (BlackboardAttribute(attID_evtx_pcmd, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["ParentCommandLine"]))), \
                                                    (BlackboardAttribute(attID_evtx_pimg, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["ParentImage"]))), \
                                                    (BlackboardAttribute(attID_evtx_ppguid, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["ParentProcessGuid"]))), \
                                                    (BlackboardAttribute(attID_evtx_ppid, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["ParentProcessId"]))), \
                                                    (BlackboardAttribute(attID_evtx_pguid, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["ProcessGuid"]))), \
                                                    (BlackboardAttribute(attID_evtx_product, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["Product"]))), \
                                                    (BlackboardAttribute(attID_evtx_tsid, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["TerminalSessionId"]))), \
                                                    (BlackboardAttribute(attID_evtx_user, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["User"]))), \
                                                    (BlackboardAttribute(attID_evtx_utc, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["UtcTime"]))), \
                                                    (BlackboardAttribute(attID_evtx_al, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["AccessList"]))), \
                                                    (BlackboardAttribute(attID_evtx_am, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["AccessMask"]))), \
                                                    (BlackboardAttribute(attID_evtx_hid, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["HandleId"]))), \
                                                    (BlackboardAttribute(attID_evtx_on, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["ObjectName"]))), \
                                                    (BlackboardAttribute(attID_evtx_os, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["ObjectServer"]))), \
                                                    (BlackboardAttribute(attID_evtx_ot, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["ObjectType"]))), \
                                                    (BlackboardAttribute(attID_evtx_pn, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["ProcessName"]))), \
                                                    (BlackboardAttribute(attID_evtx_ra, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["ResourceAttributes"]))), \
                                                    (BlackboardAttribute(attID_evtx_sdn, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["SubjectDomainName"]))), \
                                                    (BlackboardAttribute(attID_evtx_slid, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["SubjectLogonId"]))), \
                                                    (BlackboardAttribute(attID_evtx_sun, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["SubjectUserName"]))), \
                                                    (BlackboardAttribute(attID_evtx_susid, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["SubjectUserSid"]))), \
                                                    (BlackboardAttribute(attID_evtx_param1, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["param1"]))), \
                                                    (BlackboardAttribute(attID_evtx_param2, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["param2"]))), \
                                                    (BlackboardAttribute(attID_evtx_path, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["Path"])))))
                                # Post the artifact to the blackboard to display 
                                try: bboard.postArtifact(art_i, SIGMAAAnalysisIngestModuleFactory.moduleName)
                                except Blackboard.BlackboardException as e: self.log(Level.SEVERE, "Error in posting artifact "+ art_i.getDisplayName())

                            elif rule_level == "low":
                                art_l = file.newArtifact(artID_sigma_low.getTypeID())
                                # Add attributes to the artifact
                                self.log(Level.INFO, "Adding new low level SIGMA rule artifact")
                                art_l.addAttributes(((BlackboardAttribute(attID_evt_rn, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["rule_title"]))), \
                                                    (BlackboardAttribute(attID_evt_rd, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["rule_description"]))), \
                                                    (BlackboardAttribute(attID_evt_rl, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["rule_level"]))), \
                                                    (BlackboardAttribute(attID_evt_rc, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["rule_count"]))), \
                                                    (BlackboardAttribute(attID_evt_agg, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["agg"]))), \
                                                    (BlackboardAttribute(attID_evt_rid, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["row_id"]))), \
                                                    (BlackboardAttribute(attID_evt_olf, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["OriginalLogfile"]))), \
                                                    (BlackboardAttribute(attID_evtx_mn, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["MessageNumber"]))), \
                                                    (BlackboardAttribute(attID_evtx_mt, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["MessageTotal"]))), \
                                                    (BlackboardAttribute(attID_evtx_sbid, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["ScriptBlockId"]))), \
                                                    (BlackboardAttribute(attID_evtx_sbt, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["ScriptBlockText"]))), \
                                                    (BlackboardAttribute(attID_evtx_channel, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["Channel"]))), \
                                                    (BlackboardAttribute(attID_evtx_cn, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["Computer"]))), \
                                                    (BlackboardAttribute(attID_evtx_aid, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["ActivityID"]))), \
                                                    (BlackboardAttribute(attID_evtx_eid, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["EventID"]))), \
                                                    (BlackboardAttribute(attID_evtx_erid, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["EventRecordID"]))), \
                                                    (BlackboardAttribute(attID_evtx_pid, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["ProcessID"]))), \
                                                    (BlackboardAttribute(attID_evtx_tid, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["ThreadID"]))), \
                                                    (BlackboardAttribute(attID_evtx_keywords, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["Keywords"]))), \
                                                    (BlackboardAttribute(attID_evtx_level, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["Level"]))), \
                                                    (BlackboardAttribute(attID_evtx_opcode, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["Opcode"]))), \
                                                    (BlackboardAttribute(attID_evtx_guid, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["Guid"]))), \
                                                    (BlackboardAttribute(attID_evtx_pn, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["Provider_Name"]))), \
                                                    (BlackboardAttribute(attID_evtx_uid, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["UserID"]))), \
                                                    (BlackboardAttribute(attID_evtx_task, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["Task"]))), \
                                                    (BlackboardAttribute(attID_evtx_st, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["SystemTime"]))), \
                                                    (BlackboardAttribute(attID_evtx_ver, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["Version"]))), \
                                                    (BlackboardAttribute(attID_evtx_cmd, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["CommandLine"]))), \
                                                    (BlackboardAttribute(attID_evtx_company, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["Company"]))), \
                                                    (BlackboardAttribute(attID_evtx_cd, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["CurrentDirectory"]))), \
                                                    (BlackboardAttribute(attID_evtx_desc, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["Description"]))), \
                                                    (BlackboardAttribute(attID_evtx_fv, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["FileVersion"]))), \
                                                    (BlackboardAttribute(attID_evtx_sha1, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["SHA1"]))), \
                                                    (BlackboardAttribute(attID_evtx_md5, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["MD5"]))), \
                                                    (BlackboardAttribute(attID_evtx_sha256, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["SHA256"]))), \
                                                    (BlackboardAttribute(attID_evtx_imphash, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["IMPHASH"]))), \
                                                    (BlackboardAttribute(attID_evtx_hash, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["Hashes"]))), \
                                                    (BlackboardAttribute(attID_evtx_img, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["Image"]))), \
                                                    (BlackboardAttribute(attID_evtx_il, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["IntegrityLevel"]))), \
                                                    (BlackboardAttribute(attID_evtx_lguid, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["LogonGuid"]))), \
                                                    (BlackboardAttribute(attID_evtx_lid, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["LogonId"]))), \
                                                    (BlackboardAttribute(attID_evtx_ofn, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["OriginalFileName"]))), \
                                                    (BlackboardAttribute(attID_evtx_pcmd, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["ParentCommandLine"]))), \
                                                    (BlackboardAttribute(attID_evtx_pimg, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["ParentImage"]))), \
                                                    (BlackboardAttribute(attID_evtx_ppguid, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["ParentProcessGuid"]))), \
                                                    (BlackboardAttribute(attID_evtx_ppid, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["ParentProcessId"]))), \
                                                    (BlackboardAttribute(attID_evtx_pguid, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["ProcessGuid"]))), \
                                                    (BlackboardAttribute(attID_evtx_product, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["Product"]))), \
                                                    (BlackboardAttribute(attID_evtx_tsid, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["TerminalSessionId"]))), \
                                                    (BlackboardAttribute(attID_evtx_user, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["User"]))), \
                                                    (BlackboardAttribute(attID_evtx_utc, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["UtcTime"]))), \
                                                    (BlackboardAttribute(attID_evtx_al, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["AccessList"]))), \
                                                    (BlackboardAttribute(attID_evtx_am, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["AccessMask"]))), \
                                                    (BlackboardAttribute(attID_evtx_hid, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["HandleId"]))), \
                                                    (BlackboardAttribute(attID_evtx_on, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["ObjectName"]))), \
                                                    (BlackboardAttribute(attID_evtx_os, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["ObjectServer"]))), \
                                                    (BlackboardAttribute(attID_evtx_ot, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["ObjectType"]))), \
                                                    (BlackboardAttribute(attID_evtx_pn, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["ProcessName"]))), \
                                                    (BlackboardAttribute(attID_evtx_ra, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["ResourceAttributes"]))), \
                                                    (BlackboardAttribute(attID_evtx_sdn, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["SubjectDomainName"]))), \
                                                    (BlackboardAttribute(attID_evtx_slid, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["SubjectLogonId"]))), \
                                                    (BlackboardAttribute(attID_evtx_sun, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["SubjectUserName"]))), \
                                                    (BlackboardAttribute(attID_evtx_susid, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["SubjectUserSid"]))), \
                                                    (BlackboardAttribute(attID_evtx_param1, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["param1"]))), \
                                                    (BlackboardAttribute(attID_evtx_param2, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["param2"]))), \
                                                    (BlackboardAttribute(attID_evtx_path, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["Path"])))))
                                # Post the artifact to the blackboard to display 
                                try: bboard.postArtifact(art_l, SIGMAAAnalysisIngestModuleFactory.moduleName)
                                except Blackboard.BlackboardException as e: self.log(Level.SEVERE, "Error in posting artifact "+ art_l.getDisplayName()) 

                            elif rule_level == "medium":
                                art_m = file.newArtifact(artID_sigma_medium.getTypeID())
                                # Add attributes to the artifact
                                self.log(Level.INFO, "Adding new medium level SIGMA rule artifact")
                                art_m.addAttributes(((BlackboardAttribute(attID_evt_rn, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["rule_title"]))), \
                                                    (BlackboardAttribute(attID_evt_rd, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["rule_description"]))), \
                                                    (BlackboardAttribute(attID_evt_rl, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["rule_level"]))), \
                                                    (BlackboardAttribute(attID_evt_rc, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["rule_count"]))), \
                                                    (BlackboardAttribute(attID_evt_agg, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["agg"]))), \
                                                    (BlackboardAttribute(attID_evt_rid, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["row_id"]))), \
                                                    (BlackboardAttribute(attID_evt_olf, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["OriginalLogfile"]))), \
                                                    (BlackboardAttribute(attID_evtx_mn, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["MessageNumber"]))), \
                                                    (BlackboardAttribute(attID_evtx_mt, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["MessageTotal"]))), \
                                                    (BlackboardAttribute(attID_evtx_sbid, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["ScriptBlockId"]))), \
                                                    (BlackboardAttribute(attID_evtx_sbt, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["ScriptBlockText"]))), \
                                                    (BlackboardAttribute(attID_evtx_channel, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["Channel"]))), \
                                                    (BlackboardAttribute(attID_evtx_cn, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["Computer"]))), \
                                                    (BlackboardAttribute(attID_evtx_aid, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["ActivityID"]))), \
                                                    (BlackboardAttribute(attID_evtx_eid, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["EventID"]))), \
                                                    (BlackboardAttribute(attID_evtx_erid, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["EventRecordID"]))), \
                                                    (BlackboardAttribute(attID_evtx_pid, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["ProcessID"]))), \
                                                    (BlackboardAttribute(attID_evtx_tid, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["ThreadID"]))), \
                                                    (BlackboardAttribute(attID_evtx_keywords, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["Keywords"]))), \
                                                    (BlackboardAttribute(attID_evtx_level, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["Level"]))), \
                                                    (BlackboardAttribute(attID_evtx_opcode, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["Opcode"]))), \
                                                    (BlackboardAttribute(attID_evtx_guid, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["Guid"]))), \
                                                    (BlackboardAttribute(attID_evtx_pn, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["Provider_Name"]))), \
                                                    (BlackboardAttribute(attID_evtx_uid, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["UserID"]))), \
                                                    (BlackboardAttribute(attID_evtx_task, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["Task"]))), \
                                                    (BlackboardAttribute(attID_evtx_st, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["SystemTime"]))), \
                                                    (BlackboardAttribute(attID_evtx_ver, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["Version"]))), \
                                                    (BlackboardAttribute(attID_evtx_cmd, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["CommandLine"]))), \
                                                    (BlackboardAttribute(attID_evtx_company, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["Company"]))), \
                                                    (BlackboardAttribute(attID_evtx_cd, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["CurrentDirectory"]))), \
                                                    (BlackboardAttribute(attID_evtx_desc, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["Description"]))), \
                                                    (BlackboardAttribute(attID_evtx_fv, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["FileVersion"]))), \
                                                    (BlackboardAttribute(attID_evtx_sha1, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["SHA1"]))), \
                                                    (BlackboardAttribute(attID_evtx_md5, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["MD5"]))), \
                                                    (BlackboardAttribute(attID_evtx_sha256, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["SHA256"]))), \
                                                    (BlackboardAttribute(attID_evtx_imphash, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["IMPHASH"]))), \
                                                    (BlackboardAttribute(attID_evtx_hash, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["Hashes"]))), \
                                                    (BlackboardAttribute(attID_evtx_img, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["Image"]))), \
                                                    (BlackboardAttribute(attID_evtx_il, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["IntegrityLevel"]))), \
                                                    (BlackboardAttribute(attID_evtx_lguid, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["LogonGuid"]))), \
                                                    (BlackboardAttribute(attID_evtx_lid, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["LogonId"]))), \
                                                    (BlackboardAttribute(attID_evtx_ofn, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["OriginalFileName"]))), \
                                                    (BlackboardAttribute(attID_evtx_pcmd, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["ParentCommandLine"]))), \
                                                    (BlackboardAttribute(attID_evtx_pimg, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["ParentImage"]))), \
                                                    (BlackboardAttribute(attID_evtx_ppguid, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["ParentProcessGuid"]))), \
                                                    (BlackboardAttribute(attID_evtx_ppid, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["ParentProcessId"]))), \
                                                    (BlackboardAttribute(attID_evtx_pguid, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["ProcessGuid"]))), \
                                                    (BlackboardAttribute(attID_evtx_product, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["Product"]))), \
                                                    (BlackboardAttribute(attID_evtx_tsid, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["TerminalSessionId"]))), \
                                                    (BlackboardAttribute(attID_evtx_user, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["User"]))), \
                                                    (BlackboardAttribute(attID_evtx_utc, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["UtcTime"]))), \
                                                    (BlackboardAttribute(attID_evtx_al, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["AccessList"]))), \
                                                    (BlackboardAttribute(attID_evtx_am, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["AccessMask"]))), \
                                                    (BlackboardAttribute(attID_evtx_hid, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["HandleId"]))), \
                                                    (BlackboardAttribute(attID_evtx_on, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["ObjectName"]))), \
                                                    (BlackboardAttribute(attID_evtx_os, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["ObjectServer"]))), \
                                                    (BlackboardAttribute(attID_evtx_ot, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["ObjectType"]))), \
                                                    (BlackboardAttribute(attID_evtx_pn, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["ProcessName"]))), \
                                                    (BlackboardAttribute(attID_evtx_ra, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["ResourceAttributes"]))), \
                                                    (BlackboardAttribute(attID_evtx_sdn, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["SubjectDomainName"]))), \
                                                    (BlackboardAttribute(attID_evtx_slid, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["SubjectLogonId"]))), \
                                                    (BlackboardAttribute(attID_evtx_sun, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["SubjectUserName"]))), \
                                                    (BlackboardAttribute(attID_evtx_susid, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["SubjectUserSid"]))), \
                                                    (BlackboardAttribute(attID_evtx_param1, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["param1"]))), \
                                                    (BlackboardAttribute(attID_evtx_param2, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["param2"]))), \
                                                    (BlackboardAttribute(attID_evtx_path, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["Path"])))))
                                # Post the artifact to the blackboard to display 
                                try: bboard.postArtifact(art_m, SIGMAAAnalysisIngestModuleFactory.moduleName)
                                except Blackboard.BlackboardException as e: self.log(Level.SEVERE, "Error in posting artifact "+ art_m.getDisplayName()) 

                            elif rule_level == "high":
                                art_h = file.newArtifact(artID_sigma_high.getTypeID())
                                # Add attributes to the artifact
                                self.log(Level.INFO, "Adding new high level SIGMA rule artifact")
                                art_h.addAttributes(((BlackboardAttribute(attID_evt_rn, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["rule_title"]))), \
                                                    (BlackboardAttribute(attID_evt_rd, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["rule_description"]))), \
                                                    (BlackboardAttribute(attID_evt_rl, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["rule_level"]))), \
                                                    (BlackboardAttribute(attID_evt_rc, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["rule_count"]))), \
                                                    (BlackboardAttribute(attID_evt_agg, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["agg"]))), \
                                                    (BlackboardAttribute(attID_evt_rid, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["row_id"]))), \
                                                    (BlackboardAttribute(attID_evt_olf, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["OriginalLogfile"]))), \
                                                    (BlackboardAttribute(attID_evtx_mn, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["MessageNumber"]))), \
                                                    (BlackboardAttribute(attID_evtx_mt, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["MessageTotal"]))), \
                                                    (BlackboardAttribute(attID_evtx_sbid, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["ScriptBlockId"]))), \
                                                    (BlackboardAttribute(attID_evtx_sbt, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["ScriptBlockText"]))), \
                                                    (BlackboardAttribute(attID_evtx_channel, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["Channel"]))), \
                                                    (BlackboardAttribute(attID_evtx_cn, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["Computer"]))), \
                                                    (BlackboardAttribute(attID_evtx_aid, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["ActivityID"]))), \
                                                    (BlackboardAttribute(attID_evtx_eid, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["EventID"]))), \
                                                    (BlackboardAttribute(attID_evtx_erid, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["EventRecordID"]))), \
                                                    (BlackboardAttribute(attID_evtx_pid, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["ProcessID"]))), \
                                                    (BlackboardAttribute(attID_evtx_tid, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["ThreadID"]))), \
                                                    (BlackboardAttribute(attID_evtx_keywords, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["Keywords"]))), \
                                                    (BlackboardAttribute(attID_evtx_level, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["Level"]))), \
                                                    (BlackboardAttribute(attID_evtx_opcode, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["Opcode"]))), \
                                                    (BlackboardAttribute(attID_evtx_guid, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["Guid"]))), \
                                                    (BlackboardAttribute(attID_evtx_pn, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["Provider_Name"]))), \
                                                    (BlackboardAttribute(attID_evtx_uid, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["UserID"]))), \
                                                    (BlackboardAttribute(attID_evtx_task, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["Task"]))), \
                                                    (BlackboardAttribute(attID_evtx_st, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["SystemTime"]))), \
                                                    (BlackboardAttribute(attID_evtx_ver, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["Version"]))), \
                                                    (BlackboardAttribute(attID_evtx_cmd, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["CommandLine"]))), \
                                                    (BlackboardAttribute(attID_evtx_company, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["Company"]))), \
                                                    (BlackboardAttribute(attID_evtx_cd, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["CurrentDirectory"]))), \
                                                    (BlackboardAttribute(attID_evtx_desc, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["Description"]))), \
                                                    (BlackboardAttribute(attID_evtx_fv, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["FileVersion"]))), \
                                                    (BlackboardAttribute(attID_evtx_sha1, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["SHA1"]))), \
                                                    (BlackboardAttribute(attID_evtx_md5, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["MD5"]))), \
                                                    (BlackboardAttribute(attID_evtx_sha256, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["SHA256"]))), \
                                                    (BlackboardAttribute(attID_evtx_imphash, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["IMPHASH"]))), \
                                                    (BlackboardAttribute(attID_evtx_hash, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["Hashes"]))), \
                                                    (BlackboardAttribute(attID_evtx_img, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["Image"]))), \
                                                    (BlackboardAttribute(attID_evtx_il, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["IntegrityLevel"]))), \
                                                    (BlackboardAttribute(attID_evtx_lguid, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["LogonGuid"]))), \
                                                    (BlackboardAttribute(attID_evtx_lid, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["LogonId"]))), \
                                                    (BlackboardAttribute(attID_evtx_ofn, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["OriginalFileName"]))), \
                                                    (BlackboardAttribute(attID_evtx_pcmd, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["ParentCommandLine"]))), \
                                                    (BlackboardAttribute(attID_evtx_pimg, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["ParentImage"]))), \
                                                    (BlackboardAttribute(attID_evtx_ppguid, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["ParentProcessGuid"]))), \
                                                    (BlackboardAttribute(attID_evtx_ppid, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["ParentProcessId"]))), \
                                                    (BlackboardAttribute(attID_evtx_pguid, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["ProcessGuid"]))), \
                                                    (BlackboardAttribute(attID_evtx_product, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["Product"]))), \
                                                    (BlackboardAttribute(attID_evtx_tsid, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["TerminalSessionId"]))), \
                                                    (BlackboardAttribute(attID_evtx_user, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["User"]))), \
                                                    (BlackboardAttribute(attID_evtx_utc, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["UtcTime"]))), \
                                                    (BlackboardAttribute(attID_evtx_al, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["AccessList"]))), \
                                                    (BlackboardAttribute(attID_evtx_am, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["AccessMask"]))), \
                                                    (BlackboardAttribute(attID_evtx_hid, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["HandleId"]))), \
                                                    (BlackboardAttribute(attID_evtx_on, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["ObjectName"]))), \
                                                    (BlackboardAttribute(attID_evtx_os, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["ObjectServer"]))), \
                                                    (BlackboardAttribute(attID_evtx_ot, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["ObjectType"]))), \
                                                    (BlackboardAttribute(attID_evtx_pn, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["ProcessName"]))), \
                                                    (BlackboardAttribute(attID_evtx_ra, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["ResourceAttributes"]))), \
                                                    (BlackboardAttribute(attID_evtx_sdn, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["SubjectDomainName"]))), \
                                                    (BlackboardAttribute(attID_evtx_slid, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["SubjectLogonId"]))), \
                                                    (BlackboardAttribute(attID_evtx_sun, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["SubjectUserName"]))), \
                                                    (BlackboardAttribute(attID_evtx_susid, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["SubjectUserSid"]))), \
                                                    (BlackboardAttribute(attID_evtx_param1, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["param1"]))), \
                                                    (BlackboardAttribute(attID_evtx_param2, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["param2"]))), \
                                                    (BlackboardAttribute(attID_evtx_path, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["Path"])))))
                                # Post the artifact to the blackboard to display 
                                try: bboard.postArtifact(art_h, SIGMAAAnalysisIngestModuleFactory.moduleName)
                                except Blackboard.BlackboardException as e: self.log(Level.SEVERE, "Error in posting artifact "+ art_h.getDisplayName()) 

                            elif rule_level == "critical":
                                art_c = file.newArtifact(artID_sigma_crit.getTypeID())
                                # Add attributes to the artifact
                                self.log(Level.INFO, "Adding new critical level SIGMA rule artifact")
                                art_c.addAttributes(((BlackboardAttribute(attID_evt_rn, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["rule_title"]))), \
                                                    (BlackboardAttribute(attID_evt_rd, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["rule_description"]))), \
                                                    (BlackboardAttribute(attID_evt_rl, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["rule_level"]))), \
                                                    (BlackboardAttribute(attID_evt_rc, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["rule_count"]))), \
                                                    (BlackboardAttribute(attID_evt_agg, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["agg"]))), \
                                                    (BlackboardAttribute(attID_evt_rid, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["row_id"]))), \
                                                    (BlackboardAttribute(attID_evt_olf, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["OriginalLogfile"]))), \
                                                    (BlackboardAttribute(attID_evtx_mn, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["MessageNumber"]))), \
                                                    (BlackboardAttribute(attID_evtx_mt, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["MessageTotal"]))), \
                                                    (BlackboardAttribute(attID_evtx_sbid, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["ScriptBlockId"]))), \
                                                    (BlackboardAttribute(attID_evtx_sbt, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["ScriptBlockText"]))), \
                                                    (BlackboardAttribute(attID_evtx_channel, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["Channel"]))), \
                                                    (BlackboardAttribute(attID_evtx_cn, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["Computer"]))), \
                                                    (BlackboardAttribute(attID_evtx_aid, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["ActivityID"]))), \
                                                    (BlackboardAttribute(attID_evtx_eid, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["EventID"]))), \
                                                    (BlackboardAttribute(attID_evtx_erid, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["EventRecordID"]))), \
                                                    (BlackboardAttribute(attID_evtx_pid, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["ProcessID"]))), \
                                                    (BlackboardAttribute(attID_evtx_tid, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["ThreadID"]))), \
                                                    (BlackboardAttribute(attID_evtx_keywords, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["Keywords"]))), \
                                                    (BlackboardAttribute(attID_evtx_level, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["Level"]))), \
                                                    (BlackboardAttribute(attID_evtx_opcode, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["Opcode"]))), \
                                                    (BlackboardAttribute(attID_evtx_guid, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["Guid"]))), \
                                                    (BlackboardAttribute(attID_evtx_pn, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["Provider_Name"]))), \
                                                    (BlackboardAttribute(attID_evtx_uid, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["UserID"]))), \
                                                    (BlackboardAttribute(attID_evtx_task, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["Task"]))), \
                                                    (BlackboardAttribute(attID_evtx_st, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["SystemTime"]))), \
                                                    (BlackboardAttribute(attID_evtx_ver, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["Version"]))), \
                                                    (BlackboardAttribute(attID_evtx_cmd, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["CommandLine"]))), \
                                                    (BlackboardAttribute(attID_evtx_company, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["Company"]))), \
                                                    (BlackboardAttribute(attID_evtx_cd, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["CurrentDirectory"]))), \
                                                    (BlackboardAttribute(attID_evtx_desc, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["Description"]))), \
                                                    (BlackboardAttribute(attID_evtx_fv, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["FileVersion"]))), \
                                                    (BlackboardAttribute(attID_evtx_sha1, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["SHA1"]))), \
                                                    (BlackboardAttribute(attID_evtx_md5, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["MD5"]))), \
                                                    (BlackboardAttribute(attID_evtx_sha256, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["SHA256"]))), \
                                                    (BlackboardAttribute(attID_evtx_imphash, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["IMPHASH"]))), \
                                                    (BlackboardAttribute(attID_evtx_hash, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["Hashes"]))), \
                                                    (BlackboardAttribute(attID_evtx_img, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["Image"]))), \
                                                    (BlackboardAttribute(attID_evtx_il, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["IntegrityLevel"]))), \
                                                    (BlackboardAttribute(attID_evtx_lguid, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["LogonGuid"]))), \
                                                    (BlackboardAttribute(attID_evtx_lid, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["LogonId"]))), \
                                                    (BlackboardAttribute(attID_evtx_ofn, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["OriginalFileName"]))), \
                                                    (BlackboardAttribute(attID_evtx_pcmd, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["ParentCommandLine"]))), \
                                                    (BlackboardAttribute(attID_evtx_pimg, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["ParentImage"]))), \
                                                    (BlackboardAttribute(attID_evtx_ppguid, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["ParentProcessGuid"]))), \
                                                    (BlackboardAttribute(attID_evtx_ppid, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["ParentProcessId"]))), \
                                                    (BlackboardAttribute(attID_evtx_pguid, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["ProcessGuid"]))), \
                                                    (BlackboardAttribute(attID_evtx_product, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["Product"]))), \
                                                    (BlackboardAttribute(attID_evtx_tsid, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["TerminalSessionId"]))), \
                                                    (BlackboardAttribute(attID_evtx_user, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["User"]))), \
                                                    (BlackboardAttribute(attID_evtx_utc, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["UtcTime"]))), \
                                                    (BlackboardAttribute(attID_evtx_al, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["AccessList"]))), \
                                                    (BlackboardAttribute(attID_evtx_am, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["AccessMask"]))), \
                                                    (BlackboardAttribute(attID_evtx_hid, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["HandleId"]))), \
                                                    (BlackboardAttribute(attID_evtx_on, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["ObjectName"]))), \
                                                    (BlackboardAttribute(attID_evtx_os, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["ObjectServer"]))), \
                                                    (BlackboardAttribute(attID_evtx_ot, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["ObjectType"]))), \
                                                    (BlackboardAttribute(attID_evtx_pn, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["ProcessName"]))), \
                                                    (BlackboardAttribute(attID_evtx_ra, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["ResourceAttributes"]))), \
                                                    (BlackboardAttribute(attID_evtx_sdn, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["SubjectDomainName"]))), \
                                                    (BlackboardAttribute(attID_evtx_slid, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["SubjectLogonId"]))), \
                                                    (BlackboardAttribute(attID_evtx_sun, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["SubjectUserName"]))), \
                                                    (BlackboardAttribute(attID_evtx_susid, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["SubjectUserSid"]))), \
                                                    (BlackboardAttribute(attID_evtx_param1, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["param1"]))), \
                                                    (BlackboardAttribute(attID_evtx_param2, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["param2"]))), \
                                                    (BlackboardAttribute(attID_evtx_path, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["Path"])))))
                                # Post the artifact to the blackboard to display 
                                try: bboard.postArtifact(art_c, SIGMAAAnalysisIngestModuleFactory.moduleName)
                                except Blackboard.BlackboardException as e: self.log(Level.SEVERE, "Error in posting artifact "+ art_c.getDisplayName()) 
                            
                            else: self.log(Level.SEVERE, "Unknown Rule Level")
                            break

                except: self.log(Level.SEVERE, "Error in adding new Artifact")
            
                # Add attributes to the artifact
                self.log(Level.INFO, "Adding new Artifact")
                evtx_art.addAttributes(((BlackboardAttribute(attID_evt_rn, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["rule_title"]))), \
                                        (BlackboardAttribute(attID_evt_rd, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["rule_description"]))), \
                                        (BlackboardAttribute(attID_evt_rl, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["rule_level"]))), \
                                        (BlackboardAttribute(attID_evt_rc, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["rule_count"]))), \
                                        (BlackboardAttribute(attID_evt_agg, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["agg"]))), \
                                        (BlackboardAttribute(attID_evt_rid, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["row_id"]))), \
                                        (BlackboardAttribute(attID_evt_olf, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["OriginalLogfile"])))))

                # Post the artifact to the blackboard to display 
                try: bboard.postArtifact(evtx_art, SIGMAAAnalysisIngestModuleFactory.moduleName)
                except Blackboard.BlackboardException as e: self.log(Level.SEVERE, "Error in posting artifact "+ evtx_art.getDisplayName())   


        ## Linux Auditd Log Files
        if auditd_empty == False:
            # Read each line of the CSV file using DictReader
            for row in csv.DictReader(open(str(auditd_csv_file_path)), delimiter=';'):
                try:
                    for file in auditd_files:
                        # Find the index of the last occurrence of '-' in both strings
                        index = str(row["OriginalLogfile"]).rfind('-')

                        # Extract the substrings up to '-'
                        filename1 = file.getName()
                        filename2 = str(row["OriginalLogfile"])[:index]

                        # Check the file name and create and attach the artifact to the file (Summary + Rule Level)
                        if (filename1 == filename2):           
                            # Summary
                            auditd_art = file.newArtifact(artID_ioc_auditd.getTypeID())

                            # Rule Level
                            rule_level = str(row["rule_level"])

                            if rule_level == "informational":
                                art_i = file.newArtifact(artID_sigma_info.getTypeID())
                                # Add attributes to the artifact
                                self.log(Level.INFO, "Adding new Informational Level SIGMA Rule Artifact")
                                art_i.addAttributes(((BlackboardAttribute(attID_evt_rn, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["rule_title"]))), \
                                                    (BlackboardAttribute(attID_evt_rd, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["rule_description"]))), \
                                                    (BlackboardAttribute(attID_evt_rl, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["rule_level"]))), \
                                                    (BlackboardAttribute(attID_evt_rc, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["rule_count"]))), \
                                                    (BlackboardAttribute(attID_evt_agg, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["agg"]))), \
                                                    (BlackboardAttribute(attID_evt_rid, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["row_id"]))), \
                                                    (BlackboardAttribute(attID_evt_olf, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["OriginalLogfile"]))), \
                                                    (BlackboardAttribute(attID_auditd_type, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["type"]))), \
                                                    (BlackboardAttribute(attID_auditd_ts, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["timestamp"]))), \
                                                    (BlackboardAttribute(attID_auditd_arch, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["arch"]))), \
                                                    (BlackboardAttribute(attID_auditd_syscall, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["syscall"]))), \
                                                    (BlackboardAttribute(attID_auditd_success, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["success"]))), \
                                                    (BlackboardAttribute(attID_auditd_exit, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["exit"]))), \
                                                    (BlackboardAttribute(attID_auditd_a0, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["a0"]))), \
                                                    (BlackboardAttribute(attID_auditd_a1, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["a1"]))), \
                                                    (BlackboardAttribute(attID_auditd_a2, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["a2"]))), \
                                                    (BlackboardAttribute(attID_auditd_a3, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["a3"]))), \
                                                    (BlackboardAttribute(attID_auditd_items, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["items"]))), \
                                                    (BlackboardAttribute(attID_auditd_ppid, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["ppid"]))), \
                                                    (BlackboardAttribute(attID_auditd_pid, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["pid"]))), \
                                                    (BlackboardAttribute(attID_auditd_auid, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["auid"]))), \
                                                    (BlackboardAttribute(attID_auditd_uid, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["uid"]))), \
                                                    (BlackboardAttribute(attID_auditd_gid, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["gid"]))), \
                                                    (BlackboardAttribute(attID_auditd_euid, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["euid"]))), \
                                                    (BlackboardAttribute(attID_auditd_suid, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["suid"]))), \
                                                    (BlackboardAttribute(attID_auditd_fsuid, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["fsuid"]))), \
                                                    (BlackboardAttribute(attID_auditd_egid, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["egid"]))), \
                                                    (BlackboardAttribute(attID_auditd_sgid, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["sgid"]))), \
                                                    (BlackboardAttribute(attID_auditd_fsgid, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["fsgid"]))), \
                                                    (BlackboardAttribute(attID_auditd_tty, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["tty"]))), \
                                                    (BlackboardAttribute(attID_auditd_ses, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["ses"]))), \
                                                    (BlackboardAttribute(attID_auditd_comm, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["comm"]))), \
                                                    (BlackboardAttribute(attID_auditd_exe, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["exe"]))), \
                                                    (BlackboardAttribute(attID_auditd_subj, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["subj"]))), \
                                                    (BlackboardAttribute(attID_auditd_key, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["key"]))), \
                                                    (BlackboardAttribute(attID_auditd_host, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["host"]))), \
                                                    (BlackboardAttribute(attID_auditd_cwd, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["cwd"]))), \
                                                    (BlackboardAttribute(attID_auditd_item, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["item"]))), \
                                                    (BlackboardAttribute(attID_auditd_name, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["name"]))), \
                                                    (BlackboardAttribute(attID_auditd_inode, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["inode"]))), \
                                                    (BlackboardAttribute(attID_auditd_dev, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["dev"]))), \
                                                    (BlackboardAttribute(attID_auditd_mode, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["mode"]))), \
                                                    (BlackboardAttribute(attID_auditd_ouid, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["ouid"]))), \
                                                    (BlackboardAttribute(attID_auditd_ogid, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["ogid"]))), \
                                                    (BlackboardAttribute(attID_auditd_rdev, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["rdev"]))), \
                                                    (BlackboardAttribute(attID_auditd_obj, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["obj"]))), \
                                                    (BlackboardAttribute(attID_auditd_objtype, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["objtype"]))), \
                                                    (BlackboardAttribute(attID_auditd_capfp, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["capfp"]))), \
                                                    (BlackboardAttribute(attID_auditd_capfi, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["capfi"]))), \
                                                    (BlackboardAttribute(attID_auditd_capfe, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["capfe"]))), \
                                                    (BlackboardAttribute(attID_auditd_capfver, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["capfver"]))), \
                                                    (BlackboardAttribute(attID_auditd_proctitle, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["proctitle"]))), \
                                                    (BlackboardAttribute(attID_auditd_ver, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["ver"]))), \
                                                    (BlackboardAttribute(attID_auditd_format, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["format"]))), \
                                                    (BlackboardAttribute(attID_auditd_kernel, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["kernel"]))), \
                                                    (BlackboardAttribute(attID_auditd_res, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["res"]))), \
                                                    (BlackboardAttribute(attID_auditd_op, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["op"]))), \
                                                    (BlackboardAttribute(attID_auditd_acct, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["acct"]))), \
                                                    (BlackboardAttribute(attID_auditd_hostname, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["hostname"]))), \
                                                    (BlackboardAttribute(attID_auditd_addr, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["addr"]))), \
                                                    (BlackboardAttribute(attID_auditd_terminal, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["terminal"]))), \
                                                    (BlackboardAttribute(attID_auditd_argc, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["argc"])))))

                                # Post the artifact to the blackboard to display 
                                try: bboard.postArtifact(art_i, SIGMAAAnalysisIngestModuleFactory.moduleName)
                                except Blackboard.BlackboardException as e: self.log(Level.SEVERE, "Error in posting artifact "+ art_i.getDisplayName())

                            elif rule_level == "low":
                                art_l = file.newArtifact(artID_sigma_low.getTypeID())
                                # Add attributes to the artifact
                                self.log(Level.INFO, "Adding new low level SIGMA rule artifact")
                                art_l.addAttributes(((BlackboardAttribute(attID_evt_rn, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["rule_title"]))), \
                                                    (BlackboardAttribute(attID_evt_rd, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["rule_description"]))), \
                                                    (BlackboardAttribute(attID_evt_rl, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["rule_level"]))), \
                                                    (BlackboardAttribute(attID_evt_rc, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["rule_count"]))), \
                                                    (BlackboardAttribute(attID_evt_agg, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["agg"]))), \
                                                    (BlackboardAttribute(attID_evt_rid, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["row_id"]))), \
                                                    (BlackboardAttribute(attID_evt_olf, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["OriginalLogfile"]))), \
                                                    (BlackboardAttribute(attID_auditd_type, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["type"]))), \
                                                    (BlackboardAttribute(attID_auditd_ts, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["timestamp"]))), \
                                                    (BlackboardAttribute(attID_auditd_arch, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["arch"]))), \
                                                    (BlackboardAttribute(attID_auditd_syscall, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["syscall"]))), \
                                                    (BlackboardAttribute(attID_auditd_success, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["success"]))), \
                                                    (BlackboardAttribute(attID_auditd_exit, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["exit"]))), \
                                                    (BlackboardAttribute(attID_auditd_a0, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["a0"]))), \
                                                    (BlackboardAttribute(attID_auditd_a1, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["a1"]))), \
                                                    (BlackboardAttribute(attID_auditd_a2, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["a2"]))), \
                                                    (BlackboardAttribute(attID_auditd_a3, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["a3"]))), \
                                                    (BlackboardAttribute(attID_auditd_items, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["items"]))), \
                                                    (BlackboardAttribute(attID_auditd_ppid, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["ppid"]))), \
                                                    (BlackboardAttribute(attID_auditd_pid, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["pid"]))), \
                                                    (BlackboardAttribute(attID_auditd_auid, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["auid"]))), \
                                                    (BlackboardAttribute(attID_auditd_uid, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["uid"]))), \
                                                    (BlackboardAttribute(attID_auditd_gid, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["gid"]))), \
                                                    (BlackboardAttribute(attID_auditd_euid, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["euid"]))), \
                                                    (BlackboardAttribute(attID_auditd_suid, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["suid"]))), \
                                                    (BlackboardAttribute(attID_auditd_fsuid, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["fsuid"]))), \
                                                    (BlackboardAttribute(attID_auditd_egid, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["egid"]))), \
                                                    (BlackboardAttribute(attID_auditd_sgid, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["sgid"]))), \
                                                    (BlackboardAttribute(attID_auditd_fsgid, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["fsgid"]))), \
                                                    (BlackboardAttribute(attID_auditd_tty, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["tty"]))), \
                                                    (BlackboardAttribute(attID_auditd_ses, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["ses"]))), \
                                                    (BlackboardAttribute(attID_auditd_comm, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["comm"]))), \
                                                    (BlackboardAttribute(attID_auditd_exe, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["exe"]))), \
                                                    (BlackboardAttribute(attID_auditd_subj, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["subj"]))), \
                                                    (BlackboardAttribute(attID_auditd_key, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["key"]))), \
                                                    (BlackboardAttribute(attID_auditd_host, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["host"]))), \
                                                    (BlackboardAttribute(attID_auditd_cwd, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["cwd"]))), \
                                                    (BlackboardAttribute(attID_auditd_item, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["item"]))), \
                                                    (BlackboardAttribute(attID_auditd_name, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["name"]))), \
                                                    (BlackboardAttribute(attID_auditd_inode, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["inode"]))), \
                                                    (BlackboardAttribute(attID_auditd_dev, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["dev"]))), \
                                                    (BlackboardAttribute(attID_auditd_mode, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["mode"]))), \
                                                    (BlackboardAttribute(attID_auditd_ouid, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["ouid"]))), \
                                                    (BlackboardAttribute(attID_auditd_ogid, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["ogid"]))), \
                                                    (BlackboardAttribute(attID_auditd_rdev, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["rdev"]))), \
                                                    (BlackboardAttribute(attID_auditd_obj, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["obj"]))), \
                                                    (BlackboardAttribute(attID_auditd_objtype, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["objtype"]))), \
                                                    (BlackboardAttribute(attID_auditd_capfp, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["capfp"]))), \
                                                    (BlackboardAttribute(attID_auditd_capfi, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["capfi"]))), \
                                                    (BlackboardAttribute(attID_auditd_capfe, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["capfe"]))), \
                                                    (BlackboardAttribute(attID_auditd_capfver, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["capfver"]))), \
                                                    (BlackboardAttribute(attID_auditd_proctitle, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["proctitle"]))), \
                                                    (BlackboardAttribute(attID_auditd_ver, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["ver"]))), \
                                                    (BlackboardAttribute(attID_auditd_format, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["format"]))), \
                                                    (BlackboardAttribute(attID_auditd_kernel, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["kernel"]))), \
                                                    (BlackboardAttribute(attID_auditd_res, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["res"]))), \
                                                    (BlackboardAttribute(attID_auditd_op, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["op"]))), \
                                                    (BlackboardAttribute(attID_auditd_acct, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["acct"]))), \
                                                    (BlackboardAttribute(attID_auditd_hostname, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["hostname"]))), \
                                                    (BlackboardAttribute(attID_auditd_addr, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["addr"]))), \
                                                    (BlackboardAttribute(attID_auditd_terminal, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["terminal"]))), \
                                                    (BlackboardAttribute(attID_auditd_argc, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["argc"])))))
                                
                                # Post the artifact to the blackboard to display 
                                try: bboard.postArtifact(art_l, SIGMAAAnalysisIngestModuleFactory.moduleName)
                                except Blackboard.BlackboardException as e: self.log(Level.SEVERE, "Error in posting artifact "+ art_l.getDisplayName()) 

                            elif rule_level == "medium":
                                art_m = file.newArtifact(artID_sigma_medium.getTypeID())
                                # Add attributes to the artifact
                                self.log(Level.INFO, "Adding new medium level SIGMA rule artifact")
                                art_m.addAttributes(((BlackboardAttribute(attID_evt_rn, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["rule_title"]))), \
                                                    (BlackboardAttribute(attID_evt_rd, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["rule_description"]))), \
                                                    (BlackboardAttribute(attID_evt_rl, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["rule_level"]))), \
                                                    (BlackboardAttribute(attID_evt_rc, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["rule_count"]))), \
                                                    (BlackboardAttribute(attID_evt_agg, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["agg"]))), \
                                                    (BlackboardAttribute(attID_evt_rid, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["row_id"]))), \
                                                    (BlackboardAttribute(attID_evt_olf, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["OriginalLogfile"]))), \
                                                    (BlackboardAttribute(attID_auditd_type, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["type"]))), \
                                                    (BlackboardAttribute(attID_auditd_ts, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["timestamp"]))), \
                                                    (BlackboardAttribute(attID_auditd_arch, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["arch"]))), \
                                                    (BlackboardAttribute(attID_auditd_syscall, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["syscall"]))), \
                                                    (BlackboardAttribute(attID_auditd_success, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["success"]))), \
                                                    (BlackboardAttribute(attID_auditd_exit, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["exit"]))), \
                                                    (BlackboardAttribute(attID_auditd_a0, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["a0"]))), \
                                                    (BlackboardAttribute(attID_auditd_a1, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["a1"]))), \
                                                    (BlackboardAttribute(attID_auditd_a2, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["a2"]))), \
                                                    (BlackboardAttribute(attID_auditd_a3, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["a3"]))), \
                                                    (BlackboardAttribute(attID_auditd_items, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["items"]))), \
                                                    (BlackboardAttribute(attID_auditd_ppid, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["ppid"]))), \
                                                    (BlackboardAttribute(attID_auditd_pid, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["pid"]))), \
                                                    (BlackboardAttribute(attID_auditd_auid, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["auid"]))), \
                                                    (BlackboardAttribute(attID_auditd_uid, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["uid"]))), \
                                                    (BlackboardAttribute(attID_auditd_gid, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["gid"]))), \
                                                    (BlackboardAttribute(attID_auditd_euid, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["euid"]))), \
                                                    (BlackboardAttribute(attID_auditd_suid, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["suid"]))), \
                                                    (BlackboardAttribute(attID_auditd_fsuid, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["fsuid"]))), \
                                                    (BlackboardAttribute(attID_auditd_egid, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["egid"]))), \
                                                    (BlackboardAttribute(attID_auditd_sgid, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["sgid"]))), \
                                                    (BlackboardAttribute(attID_auditd_fsgid, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["fsgid"]))), \
                                                    (BlackboardAttribute(attID_auditd_tty, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["tty"]))), \
                                                    (BlackboardAttribute(attID_auditd_ses, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["ses"]))), \
                                                    (BlackboardAttribute(attID_auditd_comm, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["comm"]))), \
                                                    (BlackboardAttribute(attID_auditd_exe, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["exe"]))), \
                                                    (BlackboardAttribute(attID_auditd_subj, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["subj"]))), \
                                                    (BlackboardAttribute(attID_auditd_key, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["key"]))), \
                                                    (BlackboardAttribute(attID_auditd_host, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["host"]))), \
                                                    (BlackboardAttribute(attID_auditd_cwd, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["cwd"]))), \
                                                    (BlackboardAttribute(attID_auditd_item, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["item"]))), \
                                                    (BlackboardAttribute(attID_auditd_name, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["name"]))), \
                                                    (BlackboardAttribute(attID_auditd_inode, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["inode"]))), \
                                                    (BlackboardAttribute(attID_auditd_dev, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["dev"]))), \
                                                    (BlackboardAttribute(attID_auditd_mode, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["mode"]))), \
                                                    (BlackboardAttribute(attID_auditd_ouid, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["ouid"]))), \
                                                    (BlackboardAttribute(attID_auditd_ogid, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["ogid"]))), \
                                                    (BlackboardAttribute(attID_auditd_rdev, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["rdev"]))), \
                                                    (BlackboardAttribute(attID_auditd_obj, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["obj"]))), \
                                                    (BlackboardAttribute(attID_auditd_objtype, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["objtype"]))), \
                                                    (BlackboardAttribute(attID_auditd_capfp, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["capfp"]))), \
                                                    (BlackboardAttribute(attID_auditd_capfi, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["capfi"]))), \
                                                    (BlackboardAttribute(attID_auditd_capfe, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["capfe"]))), \
                                                    (BlackboardAttribute(attID_auditd_capfver, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["capfver"]))), \
                                                    (BlackboardAttribute(attID_auditd_proctitle, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["proctitle"]))), \
                                                    (BlackboardAttribute(attID_auditd_ver, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["ver"]))), \
                                                    (BlackboardAttribute(attID_auditd_format, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["format"]))), \
                                                    (BlackboardAttribute(attID_auditd_kernel, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["kernel"]))), \
                                                    (BlackboardAttribute(attID_auditd_res, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["res"]))), \
                                                    (BlackboardAttribute(attID_auditd_op, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["op"]))), \
                                                    (BlackboardAttribute(attID_auditd_acct, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["acct"]))), \
                                                    (BlackboardAttribute(attID_auditd_hostname, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["hostname"]))), \
                                                    (BlackboardAttribute(attID_auditd_addr, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["addr"]))), \
                                                    (BlackboardAttribute(attID_auditd_terminal, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["terminal"]))), \
                                                    (BlackboardAttribute(attID_auditd_argc, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["argc"])))))
                                
                                # Post the artifact to the blackboard to display 
                                try: bboard.postArtifact(art_m, SIGMAAAnalysisIngestModuleFactory.moduleName)
                                except Blackboard.BlackboardException as e: self.log(Level.SEVERE, "Error in posting artifact "+ art_m.getDisplayName()) 

                            elif rule_level == "high":
                                art_h = file.newArtifact(artID_sigma_high.getTypeID())
                                # Add attributes to the artifact
                                self.log(Level.INFO, "Adding new high level SIGMA rule artifact")
                                art_h.addAttributes(((BlackboardAttribute(attID_evt_rn, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["rule_title"]))), \
                                                    (BlackboardAttribute(attID_evt_rd, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["rule_description"]))), \
                                                    (BlackboardAttribute(attID_evt_rl, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["rule_level"]))), \
                                                    (BlackboardAttribute(attID_evt_rc, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["rule_count"]))), \
                                                    (BlackboardAttribute(attID_evt_agg, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["agg"]))), \
                                                    (BlackboardAttribute(attID_evt_rid, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["row_id"]))), \
                                                    (BlackboardAttribute(attID_evt_olf, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["OriginalLogfile"]))), \
                                                    (BlackboardAttribute(attID_auditd_type, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["type"]))), \
                                                    (BlackboardAttribute(attID_auditd_ts, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["timestamp"]))), \
                                                    (BlackboardAttribute(attID_auditd_arch, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["arch"]))), \
                                                    (BlackboardAttribute(attID_auditd_syscall, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["syscall"]))), \
                                                    (BlackboardAttribute(attID_auditd_success, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["success"]))), \
                                                    (BlackboardAttribute(attID_auditd_exit, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["exit"]))), \
                                                    (BlackboardAttribute(attID_auditd_a0, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["a0"]))), \
                                                    (BlackboardAttribute(attID_auditd_a1, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["a1"]))), \
                                                    (BlackboardAttribute(attID_auditd_a2, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["a2"]))), \
                                                    (BlackboardAttribute(attID_auditd_a3, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["a3"]))), \
                                                    (BlackboardAttribute(attID_auditd_items, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["items"]))), \
                                                    (BlackboardAttribute(attID_auditd_ppid, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["ppid"]))), \
                                                    (BlackboardAttribute(attID_auditd_pid, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["pid"]))), \
                                                    (BlackboardAttribute(attID_auditd_auid, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["auid"]))), \
                                                    (BlackboardAttribute(attID_auditd_uid, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["uid"]))), \
                                                    (BlackboardAttribute(attID_auditd_gid, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["gid"]))), \
                                                    (BlackboardAttribute(attID_auditd_euid, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["euid"]))), \
                                                    (BlackboardAttribute(attID_auditd_suid, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["suid"]))), \
                                                    (BlackboardAttribute(attID_auditd_fsuid, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["fsuid"]))), \
                                                    (BlackboardAttribute(attID_auditd_egid, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["egid"]))), \
                                                    (BlackboardAttribute(attID_auditd_sgid, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["sgid"]))), \
                                                    (BlackboardAttribute(attID_auditd_fsgid, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["fsgid"]))), \
                                                    (BlackboardAttribute(attID_auditd_tty, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["tty"]))), \
                                                    (BlackboardAttribute(attID_auditd_ses, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["ses"]))), \
                                                    (BlackboardAttribute(attID_auditd_comm, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["comm"]))), \
                                                    (BlackboardAttribute(attID_auditd_exe, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["exe"]))), \
                                                    (BlackboardAttribute(attID_auditd_subj, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["subj"]))), \
                                                    (BlackboardAttribute(attID_auditd_key, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["key"]))), \
                                                    (BlackboardAttribute(attID_auditd_host, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["host"]))), \
                                                    (BlackboardAttribute(attID_auditd_cwd, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["cwd"]))), \
                                                    (BlackboardAttribute(attID_auditd_item, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["item"]))), \
                                                    (BlackboardAttribute(attID_auditd_name, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["name"]))), \
                                                    (BlackboardAttribute(attID_auditd_inode, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["inode"]))), \
                                                    (BlackboardAttribute(attID_auditd_dev, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["dev"]))), \
                                                    (BlackboardAttribute(attID_auditd_mode, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["mode"]))), \
                                                    (BlackboardAttribute(attID_auditd_ouid, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["ouid"]))), \
                                                    (BlackboardAttribute(attID_auditd_ogid, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["ogid"]))), \
                                                    (BlackboardAttribute(attID_auditd_rdev, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["rdev"]))), \
                                                    (BlackboardAttribute(attID_auditd_obj, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["obj"]))), \
                                                    (BlackboardAttribute(attID_auditd_objtype, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["objtype"]))), \
                                                    (BlackboardAttribute(attID_auditd_capfp, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["capfp"]))), \
                                                    (BlackboardAttribute(attID_auditd_capfi, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["capfi"]))), \
                                                    (BlackboardAttribute(attID_auditd_capfe, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["capfe"]))), \
                                                    (BlackboardAttribute(attID_auditd_capfver, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["capfver"]))), \
                                                    (BlackboardAttribute(attID_auditd_proctitle, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["proctitle"]))), \
                                                    (BlackboardAttribute(attID_auditd_ver, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["ver"]))), \
                                                    (BlackboardAttribute(attID_auditd_format, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["format"]))), \
                                                    (BlackboardAttribute(attID_auditd_kernel, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["kernel"]))), \
                                                    (BlackboardAttribute(attID_auditd_res, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["res"]))), \
                                                    (BlackboardAttribute(attID_auditd_op, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["op"]))), \
                                                    (BlackboardAttribute(attID_auditd_acct, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["acct"]))), \
                                                    (BlackboardAttribute(attID_auditd_hostname, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["hostname"]))), \
                                                    (BlackboardAttribute(attID_auditd_addr, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["addr"]))), \
                                                    (BlackboardAttribute(attID_auditd_terminal, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["terminal"]))), \
                                                    (BlackboardAttribute(attID_auditd_argc, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["argc"])))))
                                
                                # Post the artifact to the blackboard to display 
                                try: bboard.postArtifact(art_h, SIGMAAAnalysisIngestModuleFactory.moduleName)
                                except Blackboard.BlackboardException as e: self.log(Level.SEVERE, "Error in posting artifact "+ art_h.getDisplayName()) 

                            elif rule_level == "critical":
                                art_c = file.newArtifact(artID_sigma_crit.getTypeID())
                                # Add attributes to the artifact
                                self.log(Level.INFO, "Adding new critical level SIGMA rule artifact")
                                art_c.addAttributes(((BlackboardAttribute(attID_evt_rn, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["rule_title"]))), \
                                                    (BlackboardAttribute(attID_evt_rd, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["rule_description"]))), \
                                                    (BlackboardAttribute(attID_evt_rl, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["rule_level"]))), \
                                                    (BlackboardAttribute(attID_evt_rc, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["rule_count"]))), \
                                                    (BlackboardAttribute(attID_evt_agg, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["agg"]))), \
                                                    (BlackboardAttribute(attID_evt_rid, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["row_id"]))), \
                                                    (BlackboardAttribute(attID_evt_olf, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["OriginalLogfile"]))), \
                                                    (BlackboardAttribute(attID_auditd_type, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["type"]))), \
                                                    (BlackboardAttribute(attID_auditd_ts, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["timestamp"]))), \
                                                    (BlackboardAttribute(attID_auditd_arch, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["arch"]))), \
                                                    (BlackboardAttribute(attID_auditd_syscall, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["syscall"]))), \
                                                    (BlackboardAttribute(attID_auditd_success, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["success"]))), \
                                                    (BlackboardAttribute(attID_auditd_exit, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["exit"]))), \
                                                    (BlackboardAttribute(attID_auditd_a0, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["a0"]))), \
                                                    (BlackboardAttribute(attID_auditd_a1, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["a1"]))), \
                                                    (BlackboardAttribute(attID_auditd_a2, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["a2"]))), \
                                                    (BlackboardAttribute(attID_auditd_a3, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["a3"]))), \
                                                    (BlackboardAttribute(attID_auditd_items, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["items"]))), \
                                                    (BlackboardAttribute(attID_auditd_ppid, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["ppid"]))), \
                                                    (BlackboardAttribute(attID_auditd_pid, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["pid"]))), \
                                                    (BlackboardAttribute(attID_auditd_auid, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["auid"]))), \
                                                    (BlackboardAttribute(attID_auditd_uid, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["uid"]))), \
                                                    (BlackboardAttribute(attID_auditd_gid, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["gid"]))), \
                                                    (BlackboardAttribute(attID_auditd_euid, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["euid"]))), \
                                                    (BlackboardAttribute(attID_auditd_suid, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["suid"]))), \
                                                    (BlackboardAttribute(attID_auditd_fsuid, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["fsuid"]))), \
                                                    (BlackboardAttribute(attID_auditd_egid, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["egid"]))), \
                                                    (BlackboardAttribute(attID_auditd_sgid, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["sgid"]))), \
                                                    (BlackboardAttribute(attID_auditd_fsgid, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["fsgid"]))), \
                                                    (BlackboardAttribute(attID_auditd_tty, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["tty"]))), \
                                                    (BlackboardAttribute(attID_auditd_ses, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["ses"]))), \
                                                    (BlackboardAttribute(attID_auditd_comm, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["comm"]))), \
                                                    (BlackboardAttribute(attID_auditd_exe, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["exe"]))), \
                                                    (BlackboardAttribute(attID_auditd_subj, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["subj"]))), \
                                                    (BlackboardAttribute(attID_auditd_key, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["key"]))), \
                                                    (BlackboardAttribute(attID_auditd_host, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["host"]))), \
                                                    (BlackboardAttribute(attID_auditd_cwd, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["cwd"]))), \
                                                    (BlackboardAttribute(attID_auditd_item, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["item"]))), \
                                                    (BlackboardAttribute(attID_auditd_name, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["name"]))), \
                                                    (BlackboardAttribute(attID_auditd_inode, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["inode"]))), \
                                                    (BlackboardAttribute(attID_auditd_dev, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["dev"]))), \
                                                    (BlackboardAttribute(attID_auditd_mode, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["mode"]))), \
                                                    (BlackboardAttribute(attID_auditd_ouid, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["ouid"]))), \
                                                    (BlackboardAttribute(attID_auditd_ogid, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["ogid"]))), \
                                                    (BlackboardAttribute(attID_auditd_rdev, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["rdev"]))), \
                                                    (BlackboardAttribute(attID_auditd_obj, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["obj"]))), \
                                                    (BlackboardAttribute(attID_auditd_objtype, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["objtype"]))), \
                                                    (BlackboardAttribute(attID_auditd_capfp, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["capfp"]))), \
                                                    (BlackboardAttribute(attID_auditd_capfi, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["capfi"]))), \
                                                    (BlackboardAttribute(attID_auditd_capfe, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["capfe"]))), \
                                                    (BlackboardAttribute(attID_auditd_capfver, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["capfver"]))), \
                                                    (BlackboardAttribute(attID_auditd_proctitle, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["proctitle"]))), \
                                                    (BlackboardAttribute(attID_auditd_ver, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["ver"]))), \
                                                    (BlackboardAttribute(attID_auditd_format, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["format"]))), \
                                                    (BlackboardAttribute(attID_auditd_kernel, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["kernel"]))), \
                                                    (BlackboardAttribute(attID_auditd_res, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["res"]))), \
                                                    (BlackboardAttribute(attID_auditd_op, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["op"]))), \
                                                    (BlackboardAttribute(attID_auditd_acct, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["acct"]))), \
                                                    (BlackboardAttribute(attID_auditd_hostname, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["hostname"]))), \
                                                    (BlackboardAttribute(attID_auditd_addr, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["addr"]))), \
                                                    (BlackboardAttribute(attID_auditd_terminal, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["terminal"]))), \
                                                    (BlackboardAttribute(attID_auditd_argc, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["argc"])))))
                                
                                # Post the artifact to the blackboard to display 
                                try: bboard.postArtifact(art_c, SIGMAAAnalysisIngestModuleFactory.moduleName)
                                except Blackboard.BlackboardException as e: self.log(Level.SEVERE, "Error in posting artifact "+ art_c.getDisplayName()) 
                            
                            else: self.log(Level.SEVERE, "Unknown Rule Level")
                            break

                except: self.log(Level.SEVERE, "Error in adding new Artifact")
            
                # Add attributes to the artifact
                self.log(Level.INFO, "Adding new Artifact")
                auditd_art.addAttributes(((BlackboardAttribute(attID_evt_rn, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["rule_title"]))), \
                                        (BlackboardAttribute(attID_evt_rd, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["rule_description"]))), \
                                        (BlackboardAttribute(attID_evt_rl, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["rule_level"]))), \
                                        (BlackboardAttribute(attID_evt_rc, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["rule_count"]))), \
                                        (BlackboardAttribute(attID_evt_agg, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["agg"]))), \
                                        (BlackboardAttribute(attID_evt_rid, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["row_id"]))), \
                                        (BlackboardAttribute(attID_evt_olf, SIGMAAAnalysisIngestModuleFactory.moduleName, str(row["OriginalLogfile"])))))

                # Post the artifact to the blackboard to display 
                try: bboard.postArtifact(auditd_art, SIGMAAAnalysisIngestModuleFactory.moduleName)
                except Blackboard.BlackboardException as e: self.log(Level.SEVERE, "Error in posting artifact "+ auditd_art.getDisplayName())   


        # Post a message to the ingest messages inbox (Appears at the top mail icon)
        message = IngestMessage.createMessage(IngestMessage.MessageType.DATA,
            "SIGMAA", " SIGMAA Has Been Analyzed " )
        IngestServices.getInstance().postMessage(message)

        return IngestModule.ProcessResult.OK