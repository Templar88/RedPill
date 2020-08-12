using System.Collections.Generic;
using System.Collections;
using System.Linq;
using System;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;

namespace RedPill
{
    class Program
    {
        static void Main(string[] args)
        {
            //Create a simulation
            //Simulation userLand = new Simulation();
            //Sets Defaults for simulation, can be overwritted by load from config file below *RECOMMENDED*
            int numScriptKiddies = 0; // Low-Skilled actors
            int numFMA = 20000; // Financially Motivated actors
            int numLowAndSlow = 80000; // Nation-State style actors
            int numRedTeamer = 0; // RedTeam style actors
            int userLandRebootTimer = 480; //Average time until device reboot in minutes
            int serverLandRebootTimer = 10000; //Average time until device reboot in minutes
            int alertSLA = 720; // SLA of SOC response to alerts
            string environmentChain = "User,DMZ,Server";
            string setMitigation = "none", setDataSource = "none";
            string valueMit = "0;0", valueData = "0;0";

            //check for CL arguments
            for(int i=0;i<args.Length;i++)
            {
                //forces a mitigation to specified value
                if (args[i].ToUpper() == "-SETMITIGATION")
                {
                    setMitigation = args[i+1]; 
                    valueMit = args[i+2];
                }
                //forces a datasource to specified detection value
                if(args[i].ToUpper() == "-SETDATASOURCE")
                {
                    setDataSource = args[i+1];
                    valueData = args[i+2];
                }
                //Read Config File
                if(args[i].ToUpper() == "-FILE")
                {
                    try
                    {
                        string[] lines = System.IO.File.ReadAllLines(@"Config\" + args[i+1]);
                        numScriptKiddies = Int32.Parse(lines[0].Split('=')[1]);
                        numFMA = Int32.Parse(lines[1].Split('=')[1]);
                        numLowAndSlow = Int32.Parse(lines[2].Split('=')[1]);
                        numRedTeamer = Int32.Parse(lines[3].Split('=')[1]);
                        userLandRebootTimer = Int32.Parse(lines[4].Split('=')[1]);
                        serverLandRebootTimer = Int32.Parse(lines[5].Split('=')[1]);
                        alertSLA = Int32.Parse(lines[6].Split('=')[1]);
                        environmentChain = lines[7].Split('=')[1];
                    }
                    catch (System.IO.FileNotFoundException e)
                    {
                        Console.WriteLine("File: {0} Not Found in the Config folder but -file specified (check for extension?)...Exiting",args[i+1]);
                        Console.WriteLine(e);
                        System.Environment.Exit(0);
                    }
                }
            }
            // j determines which portion of confidence interval we are in 0=low 1=average 2=high
            for (int j = 0; j < 3; j++)
			{
                int runNumScriptKiddies = numScriptKiddies;
                int runNumFMA = numFMA;
                int runNumLowAndSlow = numLowAndSlow;
                int runRedTeamer = numRedTeamer;
                // Loop through the defined environments
                for(int i=0;i<environmentChain.Split(',').Length;i++)
                {
                    //Console.WriteLine(environmentChain.Split(',')[i]);
                    Simulation sim = new Simulation();
                    Simulation.EnvironmentType runEnvironment;
                    System.Enum.TryParse(environmentChain.Split(',')[i], out runEnvironment);
                    int tempRebootTimer;
                    // If new custom environments added may need to add logic here to handle proper timer
                    if(runEnvironment == Simulation.EnvironmentType.User)
                    {
                        tempRebootTimer = userLandRebootTimer;
                    }
                    else
                    {
                        tempRebootTimer = serverLandRebootTimer;
                    }

                    sim.init(j, runNumScriptKiddies, runNumFMA, runNumLowAndSlow, runRedTeamer, Mitre.simulationType.technology, runEnvironment, tempRebootTimer, alertSLA, setMitigation, valueMit, setDataSource, valueData);
                    //Main Execution Loop
                    while(!sim.isFinished)
                    {
                        sim.update();
                    }
                    //update number of surviving agents
                    runNumScriptKiddies = sim.aggregateData.totalSuccessByType[(int)Agent.agentType.ScriptKiddie];
                    runNumFMA = sim.aggregateData.totalSuccessByType[(int)Agent.agentType.FMA];
                    runNumLowAndSlow = sim.aggregateData.totalSuccessByType[(int)Agent.agentType.LowAndSlow];
                    runRedTeamer = sim.aggregateData.totalSuccessByType[(int)Agent.agentType.RedTeamer];
                }
            }
        }  
    }
    public class AggregateData
    {
        //AggregateData is a class that all agents use to aggregate their individual results

        //success from agent point of view
        public int totalSuccess = 0;
        public int totalStealthSuccess = 0;
        public int totalSavedByShield = 0;
        public int[] totalSuccessByType;
        public int[] totalFailureByType;
        //failure from agent point of view
        public int runningFailureCount = 0;
        public int totalFailure = 0;
        public int totalBlocksByDetection = 0;
        public int totalBlocksByReboot = 0;
        public int[][] totalTTPBlocks;
        public int[][] totalTTPDetects;
        public int[][] totalTTPSuccesses;
        public int[][] totalTTPStealthSuccesses;
        public int[] totalControlBlocks;
        public int[] totalControlSoftBlocks;
        public int[] totalControlDetects;        
        public int[] totalTechnologyBlocks;
        public double[] totalTechnologyBlocksScore;
        public int[] totalTechnologySoftBlocks;
        public double[] totalTechnologySoftBlocksScore;
        public int[] totalTechnologyDetects;
        public double[] totalTechnologyDetectsScore;
        public int[] totalBlockedStages;
        public int[] totalSoftBlockedStages;
        public int[] totalSuccessStages;

        public AggregateData(Mitre mitreInfo)
        {
            totalBlockedStages = new int[Enum.GetNames(typeof(Mitre.stage)).Length];
            totalSoftBlockedStages = new int[Enum.GetNames(typeof(Mitre.stage)).Length];
            totalSuccessStages = new int[Enum.GetNames(typeof(Mitre.stage)).Length];
            totalControlBlocks = new int[mitreInfo.controlObjectList.Count];
            totalControlSoftBlocks = new int[mitreInfo.controlObjectList.Count];
            totalControlDetects = new int[mitreInfo.controlObjectList.Count];
            totalTechnologyBlocks = new int[mitreInfo.mitigationList.Count];
            totalTechnologyBlocksScore = new double[mitreInfo.mitigationList.Count];
            totalTechnologySoftBlocks = new int[mitreInfo.mitigationList.Count];
            totalTechnologySoftBlocksScore = new double[mitreInfo.mitigationList.Count];
            totalTechnologyDetects = new int[mitreInfo.sourceList.Count];
            totalTechnologyDetectsScore = new double[mitreInfo.sourceList.Count];
            totalTTPBlocks = new int[Enum.GetNames(typeof(Mitre.stage)).Length][];
            totalTTPDetects = new int[Enum.GetNames(typeof(Mitre.stage)).Length][];
            totalTTPSuccesses = new int[Enum.GetNames(typeof(Mitre.stage)).Length][];
            totalTTPStealthSuccesses = new int[Enum.GetNames(typeof(Mitre.stage)).Length][];
            totalSuccessByType = new int[Enum.GetNames(typeof(Agent.agentType)).Length];
            totalFailureByType = new int[Enum.GetNames(typeof(Agent.agentType)).Length];
            for(int i=0;i<Enum.GetNames(typeof(Mitre.stage)).Length;i++)
            {
                totalTTPBlocks[i] = new int[mitreInfo.countTTPByStage[i]];
                totalTTPDetects[i] = new int[mitreInfo.countTTPByStage[i]];
                totalTTPSuccesses[i] = new int[mitreInfo.countTTPByStage[i]];
                totalTTPStealthSuccesses[i] = new int[mitreInfo.countTTPByStage[i]];
            }
        }
    }
    public class ResultData
    {
        //Each agent as a resultData object to store individual results
        public List<string> blockedBy = new List<string>();
        public List<double> blockedByScore = new List<double>();
        public List<string> softBlockedBy = new List<string>();
        public List<double> softBlockedByScore = new List<double>();
        public List<string> detectedBy = new List<string>();
        public List<double> detectedByScore = new List<double>();
        public int[] successStage;
        public int[] blockedStage;
        public int[] softBlockedStage;
        public string[] successTTP = new string[Enum.GetNames(typeof(Mitre.stage)).Length];
        public List<Event> events = new List<Event>();
        public int failureID;
    }
    public class Agent
    {
        //Agents are the Attackers
        public enum agentType
        {
            ScriptKiddie, //Low Skill - Techniques based on mitre software list
            FMA,          // Fast Moving Actor = Techniques based on mitre APT list
            LowAndSlow,    // Slow Moving Actor = Techniques based on mitre APT list
            RedTeamer    // RedTeamer = Techniques based on mitre APT list
        }
        public Mitre mitreInfo;
        public agentType type = agentType.ScriptKiddie;
        public Event lastEvent;
        public ResultData myResultData;
        public AggregateData aggregateData;
        public List<string> initAccessSkillList;
        public List<string> knownInitAccessSkillList;
        public List<string> executionSkillList;
        public List<string> knownExecutionSkillList;        
        public List<string> persistenceSkillList;
        public List<string> knownPersistenceSkillList;
        public List<string> privilegeEscalationSkillList;
        public List<string> knownPrivilegeEscalationSkillList;
        public List<string> defenseEvasionSkillList;
        public List<string> knownDefenseEvasionSkillList;
        public List<string> credentialAccessSkillList;
        public List<string> knownCredentialAccessSkillList;
        public List<string> lateralMovementSkillList;
        public List<string> knownLateralMovementSkillList;
        public List<string> collectionSkillList;
        public List<string> knownCollectionSkillList;
        public List<string> exfiltrationSkillList;
        public List<string> knownExfiltrationSkillList;

        //total number of agents...used to compute blockscore
        public int numAgents = 0;
        // Time in minutes that agent has been potentially detectable
        public double alertTimer = 0.0;
        // Time in minutes agent has been on network
        public double totalTimer = 0.0;
        //Time in minutes unil IR catches agent
        public double alertSLA = 720;
        //Time in minutes until system reboot - can be countered by gaining persistence
        public double rebootTimer = 480;
        //Time in minutes to execute a technique  60 default 120 for low and slow actors
        public double techniqueCost = 60;
        //Current Agent evasion rating...can be raised by using defensive evasion techniques
        public float defenseEvasion = 0.0f;
        public int initialAccessIndex, executionIndex, persistenceIndex, privilegeEscalationIndex, defenseEvasionIndex, credentialAccessIndex, lateralMovementIndex, collectionIndex, exfiltrationIndex, agentID, confidenceBand;
        public bool skillsSet, hasAlerted, isDetected, isBlocked, hasPersistence;



        public Agent(Mitre mitreObj, int ID,AggregateData aggData)
        {
            mitreInfo = mitreObj;
 
            skillsSet = hasAlerted = isDetected = isBlocked = false;
            initialAccessIndex = executionIndex = persistenceIndex = privilegeEscalationIndex = defenseEvasionIndex = credentialAccessIndex = lateralMovementIndex = collectionIndex = exfiltrationIndex = 0;
            myResultData = new ResultData();
            agentID = ID;
            aggregateData = aggData;
            myResultData.successStage = new int[Enum.GetNames(typeof(Mitre.stage)).Length];
            myResultData.blockedStage = new int[Enum.GetNames(typeof(Mitre.stage)).Length];
            myResultData.softBlockedStage = new int[Enum.GetNames(typeof(Mitre.stage)).Length];

        }
        private List<string> getKnownSkillsGroup(Mitre.stage stage,int count)
        {
            //We use a hashset so that we get a unique list of skills (no repeats)
            HashSet<string> tempSkills = new HashSet<string>();
            Random r = new Random();
            while (tempSkills.Count < count)
            {
                switch(stage)
                {
                    // grab count skills from a list of possible skills that has the proper distribution of technique popularity
                    case Mitre.stage.InitialAccess:
                        tempSkills.Add(mitreInfo.groupWeightedInitialAccessList[r.Next(0,mitreInfo.groupWeightedInitialAccessList.Count)]);
                        break;
                    case Mitre.stage.Execution:
                        tempSkills.Add(mitreInfo.groupWeightedExecutionList[r.Next(0,mitreInfo.groupWeightedExecutionList.Count)]);
                        break;                    
                    case Mitre.stage.Persistence:
                        tempSkills.Add(mitreInfo.groupWeightedPersistenceList[r.Next(0,mitreInfo.groupWeightedPersistenceList.Count)]);
                        break;
                    case Mitre.stage.PrivilegeEscalation:
                        tempSkills.Add(mitreInfo.groupWeightedPrivilegeEscalationList[r.Next(0,mitreInfo.groupWeightedPrivilegeEscalationList.Count)]);
                        break;
                    case Mitre.stage.DefenseEvasion:
                        tempSkills.Add(mitreInfo.groupWeightedDefenseEvasionList[r.Next(0,mitreInfo.groupWeightedDefenseEvasionList.Count)]);
                        break;
                    case Mitre.stage.CredentialAccess:
                        tempSkills.Add(mitreInfo.groupWeightedCredentialAccessList[r.Next(0,mitreInfo.groupWeightedCredentialAccessList.Count)]);
                        break;
                    case Mitre.stage.LateralMovement:
                        tempSkills.Add(mitreInfo.groupWeightedLateralMovementList[r.Next(0,mitreInfo.groupWeightedLateralMovementList.Count)]);
                        break;
                    case Mitre.stage.Collection:
                        tempSkills.Add(mitreInfo.groupWeightedCollectionList[r.Next(0,mitreInfo.groupWeightedCollectionList.Count)]);
                        break;
                    case Mitre.stage.Exfiltration:
                        tempSkills.Add(mitreInfo.groupWeightedExfiltrationList[r.Next(0,mitreInfo.groupWeightedExfiltrationList.Count)]);
                        break;
                    default:
                        break;
                }
            }
            // convert hashset into list
            List<string> tempSkillList = new List<string>(tempSkills);
            return tempSkillList;
        }
        private List<string> getKnownSkillsSoftware(Mitre.stage stage,int count)
        {
            HashSet<string> tempSkills = new HashSet<string>();
            Random r = new Random();
            while (tempSkills.Count < count)
            {
                switch(stage)
                {
                    case Mitre.stage.InitialAccess:
                        tempSkills.Add(mitreInfo.softwareWeightedInitialAccessList[r.Next(0,mitreInfo.softwareWeightedInitialAccessList.Count)]);
                        break;
                    case Mitre.stage.Execution:
                        tempSkills.Add(mitreInfo.softwareWeightedExecutionList[r.Next(0,mitreInfo.softwareWeightedExecutionList.Count)]);
                        break;                    
                    case Mitre.stage.Persistence:
                        tempSkills.Add(mitreInfo.softwareWeightedPersistenceList[r.Next(0,mitreInfo.softwareWeightedPersistenceList.Count)]);
                        break;
                    case Mitre.stage.PrivilegeEscalation:
                        tempSkills.Add(mitreInfo.softwareWeightedPrivilegeEscalationList[r.Next(0,mitreInfo.softwareWeightedPrivilegeEscalationList.Count)]);
                        break;
                    case Mitre.stage.DefenseEvasion:
                        tempSkills.Add(mitreInfo.softwareWeightedDefenseEvasionList[r.Next(0,mitreInfo.softwareWeightedDefenseEvasionList.Count)]);
                        break;
                    case Mitre.stage.CredentialAccess:
                        tempSkills.Add(mitreInfo.softwareWeightedCredentialAccessList[r.Next(0,mitreInfo.softwareWeightedCredentialAccessList.Count)]);
                        break;
                    case Mitre.stage.LateralMovement:
                        tempSkills.Add(mitreInfo.softwareWeightedLateralMovementList[r.Next(0,mitreInfo.softwareWeightedLateralMovementList.Count)]);
                        break;
                    case Mitre.stage.Collection:
                        tempSkills.Add(mitreInfo.softwareWeightedCollectionList[r.Next(0,mitreInfo.softwareWeightedCollectionList.Count)]);
                        break;
                    case Mitre.stage.Exfiltration:
                        tempSkills.Add(mitreInfo.softwareWeightedExfiltrationList[r.Next(0,mitreInfo.softwareWeightedExfiltrationList.Count)]);
                        break;
                    default:
                        break;
                }
            }
            List<string> tempSkillList = new List<string>(tempSkills);
            return tempSkillList;
        }
        public void setType(agentType newType)
        {
            type = newType;
            switch (type)
            {   
                case agentType.ScriptKiddie:
                    if(skillsSet)
                    {
                        knownInitAccessSkillList = getKnownSkillsSoftware(Mitre.stage.InitialAccess,1);
                        knownExecutionSkillList = getKnownSkillsSoftware(Mitre.stage.Execution,1);
                        knownPersistenceSkillList = getKnownSkillsSoftware(Mitre.stage.Persistence,0);
                        knownPrivilegeEscalationSkillList = getKnownSkillsSoftware(Mitre.stage.PrivilegeEscalation,1);
                        knownDefenseEvasionSkillList = getKnownSkillsGroup(Mitre.stage.DefenseEvasion,1);
                        knownCredentialAccessSkillList = getKnownSkillsSoftware(Mitre.stage.CredentialAccess,1);
                        knownLateralMovementSkillList = getKnownSkillsSoftware(Mitre.stage.LateralMovement,1);
                        knownCollectionSkillList = getKnownSkillsSoftware(Mitre.stage.Collection,1);
                        knownExfiltrationSkillList = getKnownSkillsSoftware(Mitre.stage.Exfiltration,1);
                    }
                    break;
                case agentType.FMA:
                    if(skillsSet)
                    {
                        knownInitAccessSkillList = getKnownSkillsGroup(Mitre.stage.InitialAccess,1);
                        knownExecutionSkillList = getKnownSkillsGroup(Mitre.stage.Execution,4);
                        knownPersistenceSkillList = getKnownSkillsGroup(Mitre.stage.Persistence,3);
                        knownPrivilegeEscalationSkillList = getKnownSkillsGroup(Mitre.stage.PrivilegeEscalation,4);
                        knownDefenseEvasionSkillList = getKnownSkillsGroup(Mitre.stage.DefenseEvasion,2);
                        knownCredentialAccessSkillList = getKnownSkillsGroup(Mitre.stage.CredentialAccess,3);
                        knownLateralMovementSkillList = getKnownSkillsGroup(Mitre.stage.LateralMovement,3);
                        knownCollectionSkillList = getKnownSkillsGroup(Mitre.stage.Collection,3);
                        knownExfiltrationSkillList = getKnownSkillsGroup(Mitre.stage.Exfiltration,6);
                    }
                    break;        
                case agentType.LowAndSlow:
                    {
                        knownInitAccessSkillList = getKnownSkillsGroup(Mitre.stage.InitialAccess,1);
                        knownExecutionSkillList = getKnownSkillsGroup(Mitre.stage.Execution,4);
                        knownPersistenceSkillList = getKnownSkillsGroup(Mitre.stage.Persistence,6);
                        knownPrivilegeEscalationSkillList = getKnownSkillsGroup(Mitre.stage.PrivilegeEscalation,4);
                        knownDefenseEvasionSkillList = getKnownSkillsGroup(Mitre.stage.DefenseEvasion,6);
                        knownCredentialAccessSkillList = getKnownSkillsGroup(Mitre.stage.CredentialAccess,3);
                        knownLateralMovementSkillList = getKnownSkillsGroup(Mitre.stage.LateralMovement,3);
                        knownCollectionSkillList = getKnownSkillsGroup(Mitre.stage.Collection,3);
                        knownExfiltrationSkillList = getKnownSkillsGroup(Mitre.stage.Exfiltration,6);
                        //set default evasion
                        defenseEvasion = 0.2f;
                    }
                    break;
                case agentType.RedTeamer:
                    {
                        knownInitAccessSkillList = getKnownSkillsGroup(Mitre.stage.InitialAccess,6);
                        knownExecutionSkillList = getKnownSkillsGroup(Mitre.stage.Execution,4);
                        knownPersistenceSkillList = getKnownSkillsGroup(Mitre.stage.Persistence,6);
                        knownPrivilegeEscalationSkillList = getKnownSkillsGroup(Mitre.stage.PrivilegeEscalation,4);
                        knownDefenseEvasionSkillList = getKnownSkillsGroup(Mitre.stage.DefenseEvasion,6);
                        knownCredentialAccessSkillList = getKnownSkillsGroup(Mitre.stage.CredentialAccess,3);
                        knownLateralMovementSkillList = getKnownSkillsGroup(Mitre.stage.LateralMovement,3);
                        knownCollectionSkillList = getKnownSkillsGroup(Mitre.stage.Collection,3);
                        knownExfiltrationSkillList = getKnownSkillsGroup(Mitre.stage.Exfiltration,6);
                        //set default evasion
                        defenseEvasion = 0.2f;
                    }
                    break;
                default:
                    break;
            }
        }
        public void setSkillList(Mitre.stage stage, List<string> skills)
        {
            switch (stage)
            {
                case Mitre.stage.InitialAccess:
                    initAccessSkillList = skills;
                    break;
                case Mitre.stage.Execution:
                    executionSkillList = skills;
                    break;                
                case Mitre.stage.Persistence:
                    persistenceSkillList = skills;
                    break;
                case Mitre.stage.PrivilegeEscalation:
                    privilegeEscalationSkillList = skills;
                    break;
                case Mitre.stage.DefenseEvasion:
                    defenseEvasionSkillList = skills;
                    break;
                case Mitre.stage.CredentialAccess:
                    credentialAccessSkillList = skills;
                    break;
                case Mitre.stage.LateralMovement:
                    lateralMovementSkillList = skills;
                    break;
                case Mitre.stage.Collection:
                    collectionSkillList = skills;
                    break;
                case Mitre.stage.Exfiltration:
                    exfiltrationSkillList = skills;
                    break;
                default:
                    break;
            }
            skillsSet = true;
        }
        public string getSkill(Mitre.stage stage,int index)
        {
            switch (stage)
            {
                case Mitre.stage.InitialAccess:
                    return knownInitAccessSkillList[index];
                case Mitre.stage.Execution:
                    return knownExecutionSkillList[index];                
                case Mitre.stage.Persistence:
                    return knownPersistenceSkillList[index];
                case Mitre.stage.PrivilegeEscalation:
                    return knownPrivilegeEscalationSkillList[index];
                case Mitre.stage.DefenseEvasion:
                    return knownDefenseEvasionSkillList[index];
                case Mitre.stage.CredentialAccess:
                    return knownCredentialAccessSkillList[index];
                case Mitre.stage.LateralMovement:
                    return knownLateralMovementSkillList[index];
                case Mitre.stage.Collection:
                    return knownCollectionSkillList[index];
                case Mitre.stage.Exfiltration:
                    return knownExfiltrationSkillList[index];
                default:
                    return "Null";
            }
        }
        public bool trySkill(Mitre.stage stage)
        {
            //Console.WriteLine("agentID,init,exe,priv,cred,lat,col,exfil " + agentID + " " + initialAccessIndex + " " + executionIndex + " " + privilegeEscalationIndex + " " + credentialAccessIndex + " " + lateralMovementIndex + " " + collectionIndex + " " + exfiltrationIndex);

            bool attackSuccess = false;
            if(isBlocked)
            {
                return false;
            }
            if(stage != Mitre.stage.InitialAccess)
            {
                totalTimer += techniqueCost;
            }
            if (!hasPersistence && totalTimer > rebootTimer)
            {
                    aggregateData.totalBlocksByReboot++;
                    myResultData.blockedStage[(int)stage] = 1;
                    aggregateData.runningFailureCount++;
                    myResultData.failureID = aggregateData.runningFailureCount;
                    isBlocked = true;
                    return false;
            }
            if(isDetected)
            {
                alertTimer+=60;
                if(alertTimer >= alertSLA  && hasAlerted == false)
                {
                    aggregateData.totalBlocksByDetection++;
                    myResultData.blockedStage[(int)stage] = 1;
                    aggregateData.runningFailureCount++;
                    myResultData.failureID = aggregateData.runningFailureCount;
                    isBlocked = true;
                    hasAlerted = true;
                    return false;
                }
            }
            int agentsRemaining = numAgents-aggregateData.runningFailureCount;
            switch (stage)
            {
                case Mitre.stage.InitialAccess:
                    if(initialAccessIndex < knownInitAccessSkillList.Count)
                    {
                        string tempSkill = knownInitAccessSkillList[initialAccessIndex];
                        //use skill
                        //System.Environment.Exit(0);
                        if((mitreInfo.myEnvironment == Simulation.EnvironmentType.ExternalServer || mitreInfo.myEnvironment == Simulation.EnvironmentType.DMZ) && (tempSkill == "InitialAccess-Drive-by Compromise" ||  tempSkill == "InitialAccess-Spearphishing Attachment" ||  tempSkill == "InitialAccess-Spearphishing Link"))
                        { // if you change this must change else below
                            //Console.WriteLine(knownInitAccessSkillList[initialAccessIndex]);
                            //Console.WriteLine(mitreInfo.myEnvironment);
                            initialAccessIndex++;
                            if(initialAccessIndex == knownInitAccessSkillList.Count)
                            {
                                myResultData.blockedStage[(int)stage] = 1;
                                aggregateData.runningFailureCount++;
                                myResultData.failureID = aggregateData.runningFailureCount;
                                isBlocked = true;
                                return false;
                            }
                        }
                        //Console.WriteLine("try skill: " + knownInitAccessSkillList[initialAccessIndex] + "AgentID: " + agentID);
                        if(handleEvent(mitreInfo.tryTTP(confidenceBand,knownInitAccessSkillList[initialAccessIndex],"default",agentID, Mitre.stage.InitialAccess, defenseEvasion, agentsRemaining)))
                        {

                            myResultData.successTTP[(int)Mitre.stage.InitialAccess] = knownInitAccessSkillList[initialAccessIndex];
                            myResultData.successStage[(int)stage] = 1;
                            attackSuccess = true;
                            return attackSuccess;
                        }
                        else
                        { // if you change this must change the if block two above!
                            initialAccessIndex++;
                            if(initialAccessIndex == knownInitAccessSkillList.Count)
                            {
                                myResultData.blockedStage[(int)stage] = 1;
                                aggregateData.runningFailureCount++;
                                myResultData.failureID = aggregateData.runningFailureCount;
                                isBlocked = true;
                                return false;
                            }
                        }
                    }
                    break;
                case Mitre.stage.Execution:
                    if(executionIndex < knownExecutionSkillList.Count)
                    {
                        //use skill
                        //Console.WriteLine("Try Exec Skill");
                        //Console.WriteLine(knownExecutionSkillList[executionIndex]);
                        if(handleEvent(mitreInfo.tryTTP(confidenceBand,knownExecutionSkillList[executionIndex],"default",agentID, Mitre.stage.Execution, defenseEvasion, agentsRemaining)))
                        {
                            myResultData.successTTP[(int)Mitre.stage.Execution] = knownExecutionSkillList[executionIndex];
                            myResultData.successStage[(int)stage] = 1;
                            attackSuccess = true;
                            return attackSuccess;
                        }
                        else
                        {
                            executionIndex++;
                            if(executionIndex == knownExecutionSkillList.Count)
                            {
                                myResultData.blockedStage[(int)stage] = 1;
                                aggregateData.runningFailureCount++;
                                myResultData.failureID = aggregateData.runningFailureCount;
                                isBlocked = true;
                                return false;
                            }
                        }
                    }
                    break;
                case Mitre.stage.Persistence:
                    if(persistenceIndex < knownPersistenceSkillList.Count)
                    {
                        //use skill
                        if(handleEvent(mitreInfo.tryTTP(confidenceBand,knownPersistenceSkillList[persistenceIndex],"default",agentID, Mitre.stage.Persistence, defenseEvasion, agentsRemaining)))
                        {
                            myResultData.successTTP[(int)Mitre.stage.Persistence] = knownPersistenceSkillList[persistenceIndex];
                            myResultData.successStage[(int)stage] = 1;
                            attackSuccess = true;
                            hasPersistence = true;
                            return attackSuccess;
                        }
                        else
                        {
                            persistenceIndex++;
                            if(persistenceIndex == knownPersistenceSkillList.Count)
                            {
                                myResultData.softBlockedStage[(int)stage] = 1;
                                return false;
                            }
                        }
                    }
                    break;
                case Mitre.stage.PrivilegeEscalation:
                    if(privilegeEscalationIndex < knownPrivilegeEscalationSkillList.Count)
                    {
                        //use skill
                        if(handleEvent(mitreInfo.tryTTP(confidenceBand,knownPrivilegeEscalationSkillList[privilegeEscalationIndex],"default",agentID,Mitre.stage.PrivilegeEscalation, defenseEvasion, agentsRemaining)))
                        {
                            myResultData.successTTP[(int)Mitre.stage.PrivilegeEscalation] = knownPrivilegeEscalationSkillList[privilegeEscalationIndex];
                            myResultData.successStage[(int)stage] = 1;
                            attackSuccess = true;
                            return attackSuccess;
                        }
                        else
                        {
                            privilegeEscalationIndex++;
                            if(privilegeEscalationIndex == knownPrivilegeEscalationSkillList.Count)
                            {
                                myResultData.blockedStage[(int)stage] = 1;
                                aggregateData.runningFailureCount++;
                                myResultData.failureID = aggregateData.runningFailureCount;
                                isBlocked = true;
                                return false;
                            }
                        }
                    }
                    break;
                    case Mitre.stage.DefenseEvasion:
                    if(defenseEvasionIndex < knownDefenseEvasionSkillList.Count)
                    {
                        //use skill
                        if(handleEvent(mitreInfo.tryTTP(confidenceBand,knownDefenseEvasionSkillList[defenseEvasionIndex],"default",agentID, Mitre.stage.DefenseEvasion, defenseEvasion, agentsRemaining)))
                        {
                            myResultData.successTTP[(int)Mitre.stage.DefenseEvasion] = knownDefenseEvasionSkillList[defenseEvasionIndex];
                            myResultData.successStage[(int)stage] = 1;
                            attackSuccess = true;
                            defenseEvasion += 0.05f;  //need to analyze/benchmark/gather info
                            return attackSuccess;
                        }
                        else
                        {
                            defenseEvasionIndex++;
                            if(defenseEvasionIndex == knownDefenseEvasionSkillList.Count)
                            {
                                myResultData.softBlockedStage[(int)stage] = 1;
                                return false;
                            }
                        }
                    }
                    break;
                case Mitre.stage.CredentialAccess:
                    if(credentialAccessIndex < knownCredentialAccessSkillList.Count)
                    {
                        //use skill
                        if(handleEvent(mitreInfo.tryTTP(confidenceBand,knownCredentialAccessSkillList[credentialAccessIndex],"default",agentID,Mitre.stage.CredentialAccess, defenseEvasion, agentsRemaining)))
                        {
                            myResultData.successTTP[(int)Mitre.stage.CredentialAccess] = knownCredentialAccessSkillList[credentialAccessIndex];
                            myResultData.successStage[(int)stage] = 1;
                            attackSuccess = true;
                            return attackSuccess;
                        }
                        else
                        {
                            credentialAccessIndex++;
                            if(credentialAccessIndex == knownCredentialAccessSkillList.Count)
                            {
                                myResultData.blockedStage[(int)stage] = 1;
                                aggregateData.runningFailureCount++;
                                myResultData.failureID = aggregateData.runningFailureCount;
                                isBlocked = true;
                                return false;
                            }
                        }
                    }
                    break;
                case Mitre.stage.LateralMovement:
                    if(lateralMovementIndex < knownLateralMovementSkillList.Count)
                    {
                        //use skill
                        if(handleEvent(mitreInfo.tryTTP(confidenceBand,knownLateralMovementSkillList[lateralMovementIndex],"default",agentID,Mitre.stage.LateralMovement, defenseEvasion, agentsRemaining)))
                        {
                            myResultData.successTTP[(int)Mitre.stage.LateralMovement] = knownLateralMovementSkillList[lateralMovementIndex];
                            myResultData.successStage[(int)stage] = 1;
                            attackSuccess = true;
                            return attackSuccess;
                        }
                        else
                        {
                            lateralMovementIndex++;
                            if(lateralMovementIndex == knownLateralMovementSkillList.Count)
                            {
                                myResultData.blockedStage[(int)stage] = 1;
                                aggregateData.runningFailureCount++;
                                myResultData.failureID = aggregateData.runningFailureCount;
                                isBlocked = true;
                                return false;
                            }
                        }
                    }
                    break;
                case Mitre.stage.Collection:
                    if(collectionIndex < knownCollectionSkillList.Count)
                    {
                        //use skill
                        if(handleEvent(mitreInfo.tryTTP(confidenceBand,knownCollectionSkillList[collectionIndex],"default",agentID,Mitre.stage.Collection, defenseEvasion, agentsRemaining)))
                        {
                            myResultData.successTTP[(int)Mitre.stage.Collection] = knownCollectionSkillList[collectionIndex];
                            myResultData.successStage[(int)stage] = 1;
                            attackSuccess = true;
                            return attackSuccess;
                        }
                        else
                        {
                            collectionIndex++;
                            if(collectionIndex == knownCollectionSkillList.Count)
                            {
                                myResultData.blockedStage[(int)stage] = 1;
                                aggregateData.runningFailureCount++;
                                myResultData.failureID = aggregateData.runningFailureCount;
                                isBlocked = true;
                                return false;
                            }
                        }
                    }
                    break;
                case Mitre.stage.Exfiltration:
                    if(exfiltrationIndex < knownExfiltrationSkillList.Count)
                    {
                        //use skill
                        if(handleEvent(mitreInfo.tryTTP(confidenceBand,knownExfiltrationSkillList[exfiltrationIndex],"default",agentID,Mitre.stage.Exfiltration, defenseEvasion, agentsRemaining)))
                        {
                            myResultData.successTTP[(int)Mitre.stage.Exfiltration] = knownExfiltrationSkillList[exfiltrationIndex];
                            myResultData.successStage[(int)stage] = 1;
                            attackSuccess = true;
                            return attackSuccess;
                        }
                        else
                        {
                            exfiltrationIndex++;
                            if(exfiltrationIndex == knownExfiltrationSkillList.Count)
                            {
                                myResultData.blockedStage[(int)stage] = 1;
                                aggregateData.runningFailureCount++;
                                myResultData.failureID = aggregateData.runningFailureCount;
                                isBlocked = true;
                                return false;
                            }
                        }
                    }
                    break;
                default:
                    Console.WriteLine("Error hit default case line 407");
                    return true;
            }

                //Console.WriteLine("Error hit place it shouldn't  line 411 case");
                
                return false;
        }
        public bool handleEvent(Event nextEvent)
        {
            myResultData.events.Add(nextEvent);
            bool attackSuccess = false;
            if (!nextEvent.wasBlocked && !nextEvent.wasSoftBlocked)
            {
                attackSuccess = true;
            }
            else if (nextEvent.wasBlocked)
            {
                myResultData.blockedBy.AddRange(nextEvent.blockedByList);
                myResultData.blockedByScore.AddRange(nextEvent.blockedByScoreList);

            }
            else if (nextEvent.wasSoftBlocked)
            {
                myResultData.softBlockedBy.AddRange(nextEvent.softBlockedByList);
                myResultData.softBlockedByScore.AddRange(nextEvent.softBlockedByScoreList);
            }
            if(nextEvent.wasDetected)
            {
                isDetected = true;
                myResultData.detectedBy.AddRange(nextEvent.detectedByList);
                myResultData.detectedByScore.AddRange(nextEvent.detectedByScoreList);
            }
            return attackSuccess;
        }
        public void dumpData()
        {
            for(int j=0;j<aggregateData.totalBlockedStages.Length;j++)
            {
                aggregateData.totalBlockedStages[j] += myResultData.blockedStage[j];
                aggregateData.totalSoftBlockedStages[j] += myResultData.softBlockedStage[j];
                aggregateData.totalSuccessStages[j] += myResultData.successStage[j];
            }
            //Console.WriteLine("Time SOC Had to Respond(minutes): " + alertTimer + " to Agent: " + agentID);
            for(int i=0;i<myResultData.events.Count;i++)
            {
                //Console.WriteLine("Current Stage: " + myResultData.events[i].currentStage + " Technique: " + myResultData.events[i].TTPName + " blocked by:");
                //myResultData.events[i].blockedByList.ForEach(Console.WriteLine);
                //Console.WriteLine("Current Stage: " + myResultData.events[i].currentStage + " Technique: " + myResultData.events[i].TTPName + " detected by:");
                //myResultData.events[i].detectedByList.ForEach(Console.WriteLine);

                if(myResultData.events[i].blockedByList.Count > 0 || myResultData.events[i].softBlockedByList.Count > 0)
                {
                    //Console.WriteLine("Block stage" + (int)myResultData.events[i].currentStage);
                    //Console.WriteLine("Block TTPStageIndex " + mitreInfo.TTPNameToStageIndexValue(myResultData.events[i].TTPName,myResultData.events[i].currentStage));
                    aggregateData.totalTTPBlocks[(int)myResultData.events[i].currentStage][mitreInfo.TTPNameToStageIndexValue(myResultData.events[i].TTPName,myResultData.events[i].currentStage)]++;
                }
                if(myResultData.events[i].detectedByList.Count > 0)
                {
                    //Console.WriteLine("detection stage" + (int)myResultData.events[i].currentStage + " stage name " + myResultData.events[i].currentStage);
                    //Console.WriteLine("detection TTPStageIndex " + mitreInfo.TTPNameToStageIndexValue(myResultData.events[i].TTPName,myResultData.events[i].currentStage));
                    aggregateData.totalTTPDetects[(int)myResultData.events[i].currentStage][mitreInfo.TTPNameToStageIndexValue(myResultData.events[i].TTPName,myResultData.events[i].currentStage)]++;
                }
                if(myResultData.events[i].blockedByList.Count == 0 && myResultData.events[i].softBlockedByList.Count == 0)
                {
                    aggregateData.totalTTPSuccesses[(int)myResultData.events[i].currentStage][mitreInfo.TTPNameToStageIndexValue(myResultData.events[i].TTPName,myResultData.events[i].currentStage)]++;
                }                
                if(myResultData.events[i].detectedByList.Count + myResultData.events[i].blockedByList.Count + myResultData.events[i].softBlockedByList.Count == 0)
                {
                    aggregateData.totalTTPStealthSuccesses[(int)myResultData.events[i].currentStage][mitreInfo.TTPNameToStageIndexValue(myResultData.events[i].TTPName,myResultData.events[i].currentStage)]++;
                }
                if(myResultData.events[i].savedByShield)
                {
                    aggregateData.totalSavedByShield++;
                }
                switch(mitreInfo.mySimType)
                {
                    case Mitre.simulationType.tool:
                        if(myResultData.events[i].wasBlocked)
                        {
                            for(int j=0;j<myResultData.events[i].blockedByList.Count;j++)
                            {
                                aggregateData.totalControlBlocks[mitreInfo.ControlNameToIndexValue(myResultData.events[i].blockedByList[j])]++;
                            }
                        } 
                        if(myResultData.events[i].wasSoftBlocked)
                        {
                            for(int j=0;j<myResultData.events[i].softBlockedByList.Count;j++)
                            {
                                aggregateData.totalControlSoftBlocks[mitreInfo.ControlNameToIndexValue(myResultData.events[i].softBlockedByList[j])]++;
                            }
                        }                
                        if(myResultData.events[i].wasDetected)
                        {
                            for(int j=0;j<myResultData.events[i].detectedByList.Count;j++)
                            {
                                aggregateData.totalControlDetects[mitreInfo.ControlNameToIndexValue(myResultData.events[i].detectedByList[j])]++;
                            }
                        }
                        break;
                    case Mitre.simulationType.technology:
                        if(myResultData.events[i].wasBlocked)
                        {
                            for(int j=0;j<myResultData.events[i].blockedByList.Count;j++)
                            {
                                aggregateData.totalTechnologyBlocks[mitreInfo.MitigationNameToIndexValue(myResultData.events[i].blockedByList[j])]++;
                                aggregateData.totalTechnologyBlocksScore[mitreInfo.MitigationNameToIndexValue(myResultData.events[i].blockedByList[j])] += myResultData.events[i].blockedByScoreList[j];
                            }
                        }  
                        if(myResultData.events[i].wasSoftBlocked)
                        {
                            for(int j=0;j<myResultData.events[i].softBlockedByList.Count;j++)
                            {
                                aggregateData.totalTechnologySoftBlocks[mitreInfo.MitigationNameToIndexValue(myResultData.events[i].softBlockedByList[j])]++;
                                aggregateData.totalTechnologySoftBlocksScore[mitreInfo.MitigationNameToIndexValue(myResultData.events[i].softBlockedByList[j])] += myResultData.events[i].softBlockedByScoreList[j]; ;
                            }
                        } 
                        if(myResultData.events[i].wasDetected)
                        {
                            for(int j=0;j<myResultData.events[i].detectedByList.Count;j++)
                            {
                                //Console.WriteLine(mitreInfo.SourceNameToIndexValue(myResultData.events[i].detectedByList[j]));
                                aggregateData.totalTechnologyDetects[mitreInfo.SourceNameToIndexValue(myResultData.events[i].detectedByList[j])]++;
                                aggregateData.totalTechnologyDetectsScore[mitreInfo.SourceNameToIndexValue(myResultData.events[i].detectedByList[j])] += myResultData.events[i].detectedByScoreList[j];
                            }
                        }
                        break;
                    default:
                        break;
                }
 
            }
            
            //Console.WriteLine("");
            if(!isBlocked)
            {
                
                //Console.WriteLine("AgentID: " + agentID + " Success Path:");
                for(int i=0;i<myResultData.successTTP.Length;i++)
                {
                    //Console.WriteLine((Mitre.stage)i + ":                   " + myResultData.successTTP[i]);
                }
                aggregateData.totalSuccess++;
                aggregateData.totalSuccessByType[(int)type]++;
                if(!isDetected)
                {
                    aggregateData.totalStealthSuccess++;
                }
                //Console.WriteLine(mitreInfo.vertToCount[mitreInfo.verticalList[2]]);
            }
            else
            {
                //Console.WriteLine("AgentID: " + agentID + " Success Path:");
                for(int i=0;i<myResultData.successTTP.Length;i++)
                {
                    //Console.WriteLine((Mitre.stage)i + ":                   " + myResultData.successTTP[i]);
                }
                aggregateData.totalFailure++;
                aggregateData.totalFailureByType[(int)type]++;
            }
        }
        public void reset()
        {
            setType(type);
            skillsSet = hasAlerted = isDetected = isBlocked = false;
            initialAccessIndex = executionIndex = privilegeEscalationIndex = credentialAccessIndex = lateralMovementIndex = collectionIndex = exfiltrationIndex = defenseEvasionIndex = persistenceIndex = 0;
            alertTimer = 0.0;
            myResultData = new ResultData();
        }
    }
    public class  Simulation
    {
        //Main Simulation class
        public Mitre mitreInfo;
        public Agent[] agents;
        public AggregateData aggregateData;
        public enum EnvironmentType{User,Server,Retail,DMZ,ExternalServer}// user = user endpoints, server = internal servers, retail = retail store, DMZ = external facing servers (no crit data), ExternalServer = internal server that is exposed to web
        EnvironmentType myEnvironment;
        public int numIterations, numScriptKiddies, numFMA, numLowAndSlow, numRedTeamer, numAgents, currentIteration, confidenceBand;
        public bool isFinished;
        public string setMitigation, setDataSource, valueMit, valueData;
        public void init(int tempConfidenceBand, int tempNumScriptKiddies, int tempNumFMA, int tempNumLowAndSlow, int tempNumRedTeamer, Mitre.simulationType type, EnvironmentType environmentType, int rebootTime, int alertSLA, string tempSetMitigation, string tempValueMit, string tempSetDataSource, string tempValueData)
        {
            isFinished = false;
            myEnvironment = environmentType;
            confidenceBand = tempConfidenceBand;
            numIterations = 1;  //hard-coded for now
            //Number of agents
            numScriptKiddies = tempNumScriptKiddies;
            numFMA = tempNumFMA;
            numLowAndSlow = tempNumLowAndSlow;
            numRedTeamer = tempNumRedTeamer;
            //Mitigation and Data Source Overrides Default is no override
            setMitigation = tempSetMitigation;
            valueMit = tempValueMit;
            setDataSource = tempSetDataSource;
            valueData = tempValueData;
            numAgents = numScriptKiddies + numFMA + numLowAndSlow + numRedTeamer;
            agents = new Agent[numAgents];
            //Create Data object to store/Load all mitre related data
            mitreInfo = new Mitre(setMitigation, valueMit, setDataSource,valueData, myEnvironment);
            mitreInfo.mySimType = type;
            //Load Order is Important
            mitreInfo.LoadMonitoredSources();
            mitreInfo.LoadDetectionSources();
            mitreInfo.LoadDeployedMitigations();
            mitreInfo.LoadMitigationSources();
            mitreInfo.LoadTTP();
            //Data aggregation object
            aggregateData = new AggregateData(mitreInfo);
            // Set Skill Lists for each agent type
            for(int i=0;i<numScriptKiddies;i++)
            {
                agents[i] = new Agent(mitreInfo, i, aggregateData);
                agents[i].setSkillList(Mitre.stage.InitialAccess, mitreInfo.initialAccessList);
                agents[i].setSkillList(Mitre.stage.Execution, mitreInfo.executionList);
                agents[i].setSkillList(Mitre.stage.PrivilegeEscalation, mitreInfo.privilegeEscalationList);
                agents[i].setSkillList(Mitre.stage.DefenseEvasion, mitreInfo.defenseEvasionList);
                agents[i].setSkillList(Mitre.stage.CredentialAccess, mitreInfo.credentialAccessList);
                agents[i].setSkillList(Mitre.stage.LateralMovement, mitreInfo.lateralMovementList);
                agents[i].setSkillList(Mitre.stage.Collection, mitreInfo.collectionList);
                agents[i].setSkillList(Mitre.stage.Exfiltration, mitreInfo.exfiltrationList);
                agents[i].setType(Agent.agentType.ScriptKiddie);
                agents[i].rebootTimer = rebootTime;
                agents[i].alertSLA = alertSLA;
                agents[i].confidenceBand = confidenceBand;
                agents[i].numAgents = numAgents;
            }
            for(int i=numScriptKiddies;i<(numFMA+numScriptKiddies);i++)
            {
                agents[i] = new Agent(mitreInfo, i, aggregateData);
                agents[i].setSkillList(Mitre.stage.InitialAccess, mitreInfo.initialAccessList);
                agents[i].setSkillList(Mitre.stage.Execution, mitreInfo.executionList);
                agents[i].setSkillList(Mitre.stage.PrivilegeEscalation, mitreInfo.privilegeEscalationList);
                agents[i].setSkillList(Mitre.stage.DefenseEvasion, mitreInfo.defenseEvasionList);
                agents[i].setSkillList(Mitre.stage.CredentialAccess, mitreInfo.credentialAccessList);
                agents[i].setSkillList(Mitre.stage.LateralMovement, mitreInfo.lateralMovementList);
                agents[i].setSkillList(Mitre.stage.Collection, mitreInfo.collectionList);
                agents[i].setSkillList(Mitre.stage.Exfiltration, mitreInfo.exfiltrationList);
                agents[i].setType(Agent.agentType.FMA);
                agents[i].rebootTimer = rebootTime;
                agents[i].alertSLA = alertSLA;
                agents[i].confidenceBand = confidenceBand;
                agents[i].numAgents = numAgents;

            }            
            for(int i=(numScriptKiddies+numFMA);i<(numFMA+numScriptKiddies+numLowAndSlow);i++)
            {
                agents[i] = new Agent(mitreInfo, i, aggregateData);
                agents[i].setSkillList(Mitre.stage.InitialAccess, mitreInfo.initialAccessList);
                agents[i].setSkillList(Mitre.stage.Execution, mitreInfo.executionList);
                agents[i].setSkillList(Mitre.stage.Persistence, mitreInfo.persistenceList);
                agents[i].setSkillList(Mitre.stage.PrivilegeEscalation, mitreInfo.privilegeEscalationList);
                agents[i].setSkillList(Mitre.stage.DefenseEvasion, mitreInfo.defenseEvasionList);
                agents[i].setSkillList(Mitre.stage.CredentialAccess, mitreInfo.credentialAccessList);
                agents[i].setSkillList(Mitre.stage.LateralMovement, mitreInfo.lateralMovementList);
                agents[i].setSkillList(Mitre.stage.Collection, mitreInfo.collectionList);
                agents[i].setSkillList(Mitre.stage.Exfiltration, mitreInfo.exfiltrationList);
                agents[i].setType(Agent.agentType.LowAndSlow);
                agents[i].techniqueCost = 120; //they are moving slower...
                agents[i].rebootTimer = rebootTime;
                agents[i].alertSLA = alertSLA;
                agents[i].confidenceBand = confidenceBand;
                agents[i].numAgents = numAgents;
            }
            for(int i=(numScriptKiddies+numFMA+numLowAndSlow);i<(numFMA+numScriptKiddies+numLowAndSlow+numRedTeamer);i++)
            {
                agents[i] = new Agent(mitreInfo, i, aggregateData);
                agents[i].setSkillList(Mitre.stage.InitialAccess, mitreInfo.initialAccessList);
                agents[i].setSkillList(Mitre.stage.Execution, mitreInfo.executionList);
                agents[i].setSkillList(Mitre.stage.Persistence, mitreInfo.persistenceList);
                agents[i].setSkillList(Mitre.stage.PrivilegeEscalation, mitreInfo.privilegeEscalationList);
                agents[i].setSkillList(Mitre.stage.DefenseEvasion, mitreInfo.defenseEvasionList);
                agents[i].setSkillList(Mitre.stage.CredentialAccess, mitreInfo.credentialAccessList);
                agents[i].setSkillList(Mitre.stage.LateralMovement, mitreInfo.lateralMovementList);
                agents[i].setSkillList(Mitre.stage.Collection, mitreInfo.collectionList);
                agents[i].setSkillList(Mitre.stage.Exfiltration, mitreInfo.exfiltrationList);
                agents[i].setType(Agent.agentType.RedTeamer);
                agents[i].rebootTimer = rebootTime;
                agents[i].alertSLA = alertSLA;
                agents[i].confidenceBand = confidenceBand;
                agents[i].numAgents = numAgents;
            }
        }
        public void update()
        {
            Console.WriteLine("current Environ: " + myEnvironment);
            currentIteration++;
            switch(myEnvironment)
            {
                case EnvironmentType.User:
                    simulateStep(Mitre.stage.InitialAccess);
                    simulateStep(Mitre.stage.Execution);
                    simulateStep(Mitre.stage.Persistence);
                    simulateStep(Mitre.stage.PrivilegeEscalation);
                    simulateStep(Mitre.stage.DefenseEvasion);
                    simulateStep(Mitre.stage.CredentialAccess);
                    simulateStep(Mitre.stage.LateralMovement);
                    break;

                case EnvironmentType.Server:
                    simulateStep(Mitre.stage.Persistence);
                    simulateStep(Mitre.stage.PrivilegeEscalation);
                    simulateStep(Mitre.stage.DefenseEvasion);
                    simulateStep(Mitre.stage.CredentialAccess);
                    simulateStep(Mitre.stage.LateralMovement);
                    simulateStep(Mitre.stage.Collection);
                    simulateStep(Mitre.stage.Exfiltration);
                    break;

                case EnvironmentType.Retail:
                    simulateStep(Mitre.stage.InitialAccess);
                    simulateStep(Mitre.stage.Execution);
                    simulateStep(Mitre.stage.Persistence);
                    simulateStep(Mitre.stage.PrivilegeEscalation);
                    simulateStep(Mitre.stage.DefenseEvasion);
                    simulateStep(Mitre.stage.CredentialAccess);
                    simulateStep(Mitre.stage.LateralMovement);
                    simulateStep(Mitre.stage.Collection);
                    simulateStep(Mitre.stage.Exfiltration);
                    break;
                case EnvironmentType.DMZ:
                    simulateStep(Mitre.stage.InitialAccess);
                    simulateStep(Mitre.stage.Execution);
                    simulateStep(Mitre.stage.Persistence);
                    simulateStep(Mitre.stage.PrivilegeEscalation);
                    simulateStep(Mitre.stage.DefenseEvasion);
                    simulateStep(Mitre.stage.CredentialAccess);
                    simulateStep(Mitre.stage.LateralMovement);
                    break;
                case EnvironmentType.ExternalServer:
                    simulateStep(Mitre.stage.InitialAccess);
                    simulateStep(Mitre.stage.Execution);
                    simulateStep(Mitre.stage.Persistence);
                    simulateStep(Mitre.stage.PrivilegeEscalation);
                    simulateStep(Mitre.stage.DefenseEvasion);
                    simulateStep(Mitre.stage.CredentialAccess);
                    simulateStep(Mitre.stage.LateralMovement);
                    simulateStep(Mitre.stage.Collection);
                    simulateStep(Mitre.stage.Exfiltration);
                    break;

                default:
                    Console.WriteLine("No Environment Set");
                    break;
            }


            for(int i=0;i<agents.Length;i++)
            {
                agents[i].dumpData();
                agents[i].reset();
            }
            Console.WriteLine("Total Succesful Attacks: " + aggregateData.totalSuccess);
            Console.WriteLine("Total Stealth Attacks: " + aggregateData.totalStealthSuccess);
            Console.WriteLine("Total Failed Attacks: " + aggregateData.totalFailure);
            Console.WriteLine("Total Blocks via IR: " + aggregateData.totalBlocksByDetection);
            Console.WriteLine("Total Blocks via Reboot: " + aggregateData.totalBlocksByReboot);
            for(int i=0;i<aggregateData.totalBlockedStages.Length;i++)
            {
                Console.WriteLine("Total blocks at stage " + (Mitre.stage)i + ": " + aggregateData.totalBlockedStages[i]);
                Console.WriteLine("Total softblocks at stage " + (Mitre.stage)i + ": " + aggregateData.totalSoftBlockedStages[i]);
                Console.WriteLine("Total successes at stage " + (Mitre.stage)i + ": " + aggregateData.totalSuccessStages[i]);
            }
            if(mitreInfo.mySimType == Mitre.simulationType.technology)
            {
                List<Mitigation> mitigations = mitreInfo.getMitigations();
                for(int i=0;i<mitigations.Count;i++)
                {
                    Console.WriteLine(mitigations[i].name +": " + mitigations[i].low + ";" + mitigations[i].high);
                }
                List<Source> sources = mitreInfo.getSources();
                for(int i=0;i<sources.Count;i++)
                {
                    Console.WriteLine(sources[i].name +": " + sources[i].low + ";" + sources[i].high);
                }
            }

            for(int i=0;i<aggregateData.totalControlBlocks.Length;i++)
            {
                if(aggregateData.totalControlBlocks[i] > 0)
                {
                    //Console.WriteLine("Total Blocks by " + mitreInfo.controlObjectList[i].tool + ": " + aggregateData.totalControlBlocks[i]);
                }
            }
            for(int i=0;i<aggregateData.totalControlDetects.Length;i++)
            {
                if(aggregateData.totalControlDetects[i] > 0)
                {
                    //Console.WriteLine("Total Detects by " + mitreInfo.controlObjectList[i].tool + ": " + aggregateData.totalControlDetects[i]);
                }
            }

            for(int i=0;i<aggregateData.totalTechnologyBlocks.Length;i++)
            {
                //if(aggregateData.totalTechnologyBlocks[i] > 0)
                //{
                    Console.WriteLine("Total Blocks by " + mitreInfo.mitigationList[i].name + ": " + aggregateData.totalTechnologyBlocks[i]);
                    Console.WriteLine("Total BlocksScore by " + mitreInfo.mitigationList[i].name + ": " + aggregateData.totalTechnologyBlocksScore[i]);
                //}
            }
            for(int i=0;i<aggregateData.totalTechnologySoftBlocks.Length;i++)
            {
                //if(aggregateData.totalTechnologySoftBlocks[i] > 0)
                //{
                    Console.WriteLine("Total Soft Blocks by " + mitreInfo.mitigationList[i].name + ": " + aggregateData.totalTechnologySoftBlocks[i]);
                    Console.WriteLine("Total Soft BlocksScore by " + mitreInfo.mitigationList[i].name + ": " + aggregateData.totalTechnologySoftBlocksScore[i]);
                //}
            }
            for(int i=0;i<aggregateData.totalTechnologyDetects.Length;i++)
            {
                //if(aggregateData.totalTechnologyDetects[i] > 0)
                //{
                    Console.WriteLine("Total Detects by " + mitreInfo.sourceList[i].name + ": " + aggregateData.totalTechnologyDetects[i]);
                    Console.WriteLine("Total DetectsScore by " + mitreInfo.sourceList[i].name + ": " + aggregateData.totalTechnologyDetectsScore[i]);
                //}
            }

            int k=0;
            for(int i=0;i<aggregateData.totalTTPBlocks.Length;i++)
            {
                for(int j=0;j<aggregateData.totalTTPBlocks[i].Length;j++)
                {
                    //if(aggregateData.totalTTPBlocks[i][j] > 0)
                    //{
                        Console.WriteLine("Total Blocks of " + mitreInfo.TTPNameList[k] + ": " + aggregateData.totalTTPBlocks[i][j]);
                    //}                    
                    //if(aggregateData.totalTTPDetects[i][j] > 0)
                    //{
                        Console.WriteLine("Total Detects of " + mitreInfo.TTPNameList[k] + ": " + aggregateData.totalTTPDetects[i][j]);
                    //}
                    //if(aggregateData.totalTTPStealthSuccesses[i][j] > 0)
                    //{
                        Console.WriteLine("Total Stealth Successes of " + mitreInfo.TTPNameList[k] + ": " + aggregateData.totalTTPStealthSuccesses[i][j]);
                    //}
                    //if(aggregateData.totalTTPSuccesses[i][j] > 0)
                    //{
                        Console.WriteLine("Total Successes of " + mitreInfo.TTPNameList[k] + ": " + aggregateData.totalTTPSuccesses[i][j]);
                    //}


                    k++;
                }
            }
            /*
            for(int i=0;i<mitreInfo.controlObjectList.Count;i++)
            {
                Console.WriteLine(mitreInfo.controlObjectList[i].tool + "Blocked:");
                mitreInfo.controlObjectList[i].agentIDBlockList.ForEach(Console.WriteLine);
                Console.WriteLine(mitreInfo.controlObjectList[i].tool + "Detected:");
                mitreInfo.controlObjectList[i].agentIDDetectList.ForEach(Console.WriteLine);
            }
            */
            if(currentIteration == numIterations) isFinished = true;           
        }
        public void simulateStep(Mitre.stage nextStage)
        {
            for(int i=0;i<agents.Length;i++)
            {
                switch(nextStage)
                {
                    case Mitre.stage.InitialAccess:
                        for(int j=0;j<agents[i].knownInitAccessSkillList.Count;j++)
                        {
                            if(agents[i].trySkill(Mitre.stage.InitialAccess))
                            {
                                break;
                            }
                        }
                        break;
                    case Mitre.stage.Execution:
                        for(int j=0;j<agents[i].knownExecutionSkillList.Count;j++)
                        {
                            if(agents[i].trySkill(Mitre.stage.Execution))
                            {
                                break;
                            }
                        }
                        break;                    
                    case Mitre.stage.Persistence:
                        for(int j=0;j<agents[i].knownPersistenceSkillList.Count;j++)
                        {
                            if(agents[i].trySkill(Mitre.stage.Persistence))
                            {
                                break;
                            }
                        }
                        break;
                    case Mitre.stage.PrivilegeEscalation:
                        for(int j=0;j<agents[i].knownPrivilegeEscalationSkillList.Count;j++)
                        {
                            if(agents[i].trySkill(Mitre.stage.PrivilegeEscalation))
                            {
                                break;
                            }
                        }
                        break;
                    case Mitre.stage.DefenseEvasion:
                        for(int j=0;j<agents[i].knownDefenseEvasionSkillList.Count;j++)
                        {
                            if(agents[i].trySkill(Mitre.stage.DefenseEvasion))
                            {
                                break;
                            }
                        }
                        break;
                    case Mitre.stage.CredentialAccess:
                        for(int j=0;j<agents[i].knownCredentialAccessSkillList.Count;j++)
                        {
                            if(agents[i].trySkill(Mitre.stage.CredentialAccess))
                            {
                                break;
                            }
                        }
                        break;
                    case Mitre.stage.LateralMovement:
                        for(int j=0;j<agents[i].knownLateralMovementSkillList.Count;j++)
                        {
                            if(agents[i].trySkill(Mitre.stage.LateralMovement))
                            {
                                break;
                            }
                        }
                        break;
                    case Mitre.stage.Collection:
                        for(int j=0;j<agents[i].knownCollectionSkillList.Count;j++)
                        {
                            if(agents[i].trySkill(Mitre.stage.Collection))
                            {
                                break;
                            }
                        }
                        break;
                    case Mitre.stage.Exfiltration:
                        for(int j=0;j<agents[i].knownExfiltrationSkillList.Count;j++)
                        {
                            if(agents[i].trySkill(Mitre.stage.Exfiltration))
                            {
                                break;
                            }
                        }
                        break;
                    default:
                        break;
                }
            }
        }
    }
}