using System.Collections.Generic;
using System.IO;
using System.Linq;
using System;
using System.Runtime.InteropServices;

namespace RedPill
{
    public class SourceMapData
    {
        //sources of data for a particular Technique
        public List<string> sources = new List<string>();
        public Mitre.stage stage;
        public float lowValue, highValue;
        public string TTPName;
        public string TTPID;
        public int TTPIndex;
        public bool isMonitored = false;
        public SourceMapData(string name, string id, int index, Mitre.stage tempStage)
        {
            TTPName = name;
            TTPID = id;
            TTPIndex = index;
            stage = tempStage;
        }
    }
    public class MitigationMapData
    {
        //mitigations particular Technique
        public List<string> mitigations = new List<string>();
        public Mitre.stage stage;
        public string TTPName;
        public string TTPID;
        public int TTPIndex;
        public bool isMitigated = false;
        public MitigationMapData(string name, string id, int index, Mitre.stage tempStage)
        {
            TTPName = name;
            TTPID = id;
            TTPIndex = index;
            stage = tempStage;
        } 
    }
    public class Mitigation
    {
        public string ID, name;
        public float low,high,avg;
        public Mitigation(string tempID, string tempName, float tempLow, float tempHigh)
        {
            ID = tempID;
            name = tempName;
            low = tempLow;
            high = tempHigh;
            avg = (low+high)/(float)2.0;
        }
    }
    public class Source
    {
        public string name;
        public float low,high,avg;
        public Source(string tempName, float tempLow, float tempHigh)
        {
            name = tempName;
            low = tempLow;
            high = tempHigh;
            avg = (low+high)/(float)2.0;
        }
    }

    public class Event
    {
        public bool wasBlocked = false;
        public bool wasSoftBlocked = false;
        public bool wasDetected = false;
        public bool savedByShield = false;
        public float successScore = 0.0f;
        public List<string> detectedByList = new List<string>();
        public List<double> detectedByScoreList = new List<double>();
        public List<string> blockedByList = new List<string>();
        public List<double> blockedByScoreList = new List<double>();
        public List<string> softBlockedByList = new List<string>();
        public List<double> softBlockedByScoreList = new List<double>();
        public Mitre.stage currentStage;
        public string TTPName;

    }
    public class Technology
    {
        public string name;
        public List<string> agentIDBlockList = new List<string>();
        public List<string> agentIDSoftBlockList = new List<string>();
        public List<string> agentIDDetectList = new List<string>();
        public List<Event> myEvents = new List<Event>();

        public Technology(string tempName)
        {
            name = tempName;
        }

    }
    public class Control
    {
        public string tool;
        public string Location;
        public string Brand;
        public List<string> agentIDBlockList = new List<string>();
        public List<string> agentIDSoftBlockList = new List<string>();
        public List<string> agentIDDetectList = new List<string>();
        public List<Event> myEvents = new List<Event>();
        public List<float> blockValueList = new List<float>();
        public List<float> detectValueList = new List<float>();
        public Control(string name)
        {
            tool = name;
        }
    }
    public class Mitre
    {
        public List<string> TTPIDList = new List<string>();
        public List<string> TTPNameList = new List<string>();
        public List<int> TTPGroupCountList = new List<int>();
        public List<int> TTPSoftwareCountList = new List<int>();

        public List<string> initialAccessList = new List<string>();
        public List<string> groupWeightedInitialAccessList = new List<string>();
        public List<string> softwareWeightedInitialAccessList = new List<string>();

        public List<string> executionList = new List<string>();
        public List<string> groupWeightedExecutionList = new List<string>();
        public List<string> softwareWeightedExecutionList = new List<string>();

        public List<string> persistenceList = new List<string>();
        public List<string> groupWeightedPersistenceList = new List<string>();
        public List<string> softwareWeightedPersistenceList = new List<string>();

        public List<string> privilegeEscalationList = new List<string>();
        public List<string> groupWeightedPrivilegeEscalationList = new List<string>();
        public List<string> softwareWeightedPrivilegeEscalationList = new List<string>();

        public List<string> defenseEvasionList = new List<string>();
        public List<string> groupWeightedDefenseEvasionList = new List<string>();
        public List<string> softwareWeightedDefenseEvasionList = new List<string>();

        public List<string> credentialAccessList = new List<string>();
        public List<string> groupWeightedCredentialAccessList = new List<string>();
        public List<string> softwareWeightedCredentialAccessList = new List<string>();

        public List<string> lateralMovementList = new List<string>();
        public List<string> groupWeightedLateralMovementList = new List<string>();
        public List<string> softwareWeightedLateralMovementList = new List<string>();

        public List<string> collectionList = new List<string>();
        public List<string> groupWeightedCollectionList = new List<string>();
        public List<string> softwareWeightedCollectionList = new List<string>();

        public List<string> exfiltrationList = new List<string>();
        public List<string> groupWeightedExfiltrationList = new List<string>();
        public List<string> softwareWeightedExfiltrationList = new List<string>();

        public List<string> controlsList = new List<string>();
        public List<Control> controlObjectList = new List<Control>();

        public List<string> monitoredSources = new List<string>();
        public List<string> nonMonitoredSources = new List<string>();

        public List<string> mitigatedTTPs = new List<string>();
        public List<string> nonMitgatedSources = new List<string>();

        public List<Source> sourceList = new List<Source>();
        public List<SourceMapData> sourceMapDataObjectList = new List<SourceMapData>();

        //public List<MitigationData> mitigationDataObjectList = new List<MitigationData>();
        public List<Mitigation> mitigationList = new List<Mitigation>();
        public List<MitigationMapData> mitigationMapDataObjectList = new List<MitigationMapData>();

        public Dictionary<string, int> vertToCount = new Dictionary<string, int>();
        public List<string> verticalList = new List<string>();
        

        private string tempStage;
        public string setMitigation, setDataSource;
        public string valueMit, ValueData;
        public enum stage{InitialAccess,Execution,Persistence,PrivilegeEscalation,DefenseEvasion,CredentialAccess,LateralMovement,Collection,Exfiltration}
        public enum bonusStage{Persistence,DefenseEvasion,Discovery,CommandAndControl}
        public enum simulationType{tool,technology}
        public simulationType mySimType = simulationType.tool;
        public Simulation.EnvironmentType myEnvironment;
        public int[] countTTPByStage = new int[Enum.GetNames(typeof(Mitre.stage)).Length];
        public Dictionary<stage,string> formalStage = new Dictionary<stage, string>();

        public Mitre(string tempSetMitigation, string tempValueMit, string tempSetDataSource, string tempValueData, Simulation.EnvironmentType tempType)
        {
            setMitigation = tempSetMitigation;
            valueMit = tempValueMit;
            setDataSource = tempSetDataSource;
            ValueData = tempValueData;
            myEnvironment = tempType;
            formalStage.Add(stage.InitialAccess,"initial-access");
            formalStage.Add(stage.Execution,"execution");
            formalStage.Add(stage.Persistence,"persistence");
            formalStage.Add(stage.PrivilegeEscalation,"privilege-escalation");
            formalStage.Add(stage.DefenseEvasion,"defense-evasion");
            formalStage.Add(stage.CredentialAccess,"credential-access");
            formalStage.Add(stage.LateralMovement,"lateral-movement");
            formalStage.Add(stage.Collection,"collection");
            formalStage.Add(stage.Exfiltration,"exfiltration");
            
        }

        public int TTPNameToIndexValue(string ttp)
        {
            return TTPNameList.IndexOf(ttp);
        }
        public int TTPNameToStageIndexValue(string ttp, stage ttpStage)
        {
            return (TTPNameList.IndexOf(ttp) - vertToCount[verticalList[(int)ttpStage]]);
        }
        public int ControlNameToIndexValue(string control)
        {
            return controlObjectList.IndexOf(controlObjectList.Find(i => i.tool == control));
        }
        public int SourceMapDataTTPNameToIndexValue(string ttp)
        {
            return sourceMapDataObjectList.IndexOf(sourceMapDataObjectList.Find(i => i.TTPName == ttp));
        } 
        public string SourceMapDataTTPNameToTTPID(string ttp)
        {
            return sourceMapDataObjectList.Find(i => i.TTPName == ttp).TTPID;
        }  
        public int SourceNameToIndexValue(string sName)
        {
            return sourceList.IndexOf(sourceList.Find(i => i.name == sName));
        }
        public int MitigationNameToIndexValue(string mName)
        {
            return mitigationList.IndexOf(mitigationList.Find(i => i.name == mName));
        }
        public int MitigationMapDataTTPNameToIndexValue(string mTTP)
        {
            return mitigationMapDataObjectList.IndexOf(mitigationMapDataObjectList.Find(i => i.TTPName == mTTP));
        }
        public string MitigationMapDataTTPNameToTTPID(string mTTP)
        {
            return mitigationMapDataObjectList.Find(i => i.TTPName == mTTP).TTPID;
        }
        public List<Mitigation> getMitigations()
        {
            return mitigationList;
        }
        public List<Source> getSources()
        {
            return sourceList;
        }
        public Event tryTTP(int confBand, string nameTTP, string location, int tempAgentID, stage currentStage, float tempEvasionShield, int agentsRemaining)
        {
            int index = TTPNameToIndexValue(nameTTP);
            Random r = new Random();
            Event tempEvent = new Event();
            tempEvent.currentStage = currentStage;
            tempEvent.TTPName = nameTTP;
            //double rand;
            double evasionShield = tempEvasionShield;
            //Kludge for LAS actor

            //TODO implement location handling
            switch(mySimType)
            {
                case simulationType.tool:
                    for(int i=0;i<controlObjectList.Count;i++)
                    {
                        //rand = r.NextDouble();
                        //Console.WriteLine(controlObjectList[i].tool + " " + TTPNameList[index] + " " + controlObjectList[i].detectValueList[index]);
                        if(controlObjectList[i].blockValueList[index] >=  r.NextDouble())
                        {
                            if (evasionShield >= r.NextDouble())
                            {
                                tempEvent.savedByShield = true;
                                continue;
                            }
                            if(System.Enum.IsDefined(typeof(bonusStage),tempEvent.currentStage.ToString()))
                            {
                                tempEvent.wasSoftBlocked = true;
                                tempEvent.softBlockedByList.Add(controlObjectList[i].tool);
                                controlObjectList[i].agentIDSoftBlockList.Add(tempAgentID.ToString());
                            }
                            else
                            {
                                tempEvent.wasBlocked = true;
                                tempEvent.blockedByList.Add(controlObjectList[i].tool);
                                controlObjectList[i].agentIDBlockList.Add(tempAgentID.ToString());
                            }

                        }
                        if(controlObjectList[i].detectValueList[index] >=  r.NextDouble())
                        {
                            if (evasionShield >= r.NextDouble())
                            {
                                tempEvent.savedByShield = true;
                                continue;
                            }
                            tempEvent.wasDetected = true;
                            tempEvent.detectedByList.Add(controlObjectList[i].tool);
                            controlObjectList[i].agentIDDetectList.Add(tempAgentID.ToString());
                        }
                        controlObjectList[i].myEvents.Add(tempEvent);
                    }
                break;
                case simulationType.technology:
                    int sourceMapDataIndex = SourceMapDataTTPNameToIndexValue(nameTTP);
                    int mitigationMapDataIndex = MitigationMapDataTTPNameToIndexValue(nameTTP);
                    //Console.WriteLine("trying skill: " + nameTTP);
                    //rand = r.NextDouble();
                    //Console.WriteLine(nameTTP + " " + sourceMapDataIndex);
                    if(sourceMapDataObjectList[sourceMapDataIndex].isMonitored)
                    {
                        for (int i=0;i<sourceMapDataObjectList[sourceMapDataIndex].sources.Count;i++)
                        {
                            if (evasionShield >= r.NextDouble())
                            {
                                tempEvent.savedByShield = true;
                                continue;
                            }

                            float sourceVal=0.0f;
                            if(confBand == 0) sourceVal = sourceList[SourceNameToIndexValue(sourceMapDataObjectList[sourceMapDataIndex].sources[i])].low;
                            else if(confBand == 1) sourceVal = sourceList[SourceNameToIndexValue(sourceMapDataObjectList[sourceMapDataIndex].sources[i])].avg;
                            else if(confBand ==2) sourceVal = sourceList[SourceNameToIndexValue(sourceMapDataObjectList[sourceMapDataIndex].sources[i])].high;
                            else
                            {
                                Console.WriteLine("Impossible ConfBand.  Exiting...");
                                System.Environment.Exit(-1);
                            }

                            if( sourceVal >= r.NextDouble())
                            {
                                tempEvent.wasDetected = true;
                                tempEvent.detectedByList.Add(sourceMapDataObjectList[sourceMapDataIndex].sources[i]);
                                tempEvent.detectedByScoreList.Add(1.0/agentsRemaining);
                            }
                        }
                    }
                    if(mitigationMapDataObjectList[mitigationMapDataIndex].isMitigated)
                    {
                        for (int i=0;i<mitigationMapDataObjectList[mitigationMapDataIndex].mitigations.Count;i++)
                        {

                            float mitValue=0.0f;
                            if(confBand == 0) mitValue = mitigationList[MitigationNameToIndexValue(mitigationMapDataObjectList[mitigationMapDataIndex].mitigations[i])].low;
                            else if(confBand == 1) mitValue = mitigationList[MitigationNameToIndexValue(mitigationMapDataObjectList[mitigationMapDataIndex].mitigations[i])].avg;
                            else if(confBand == 2) mitValue = mitigationList[MitigationNameToIndexValue(mitigationMapDataObjectList[mitigationMapDataIndex].mitigations[i])].high;
                            else
                            {
                                Console.WriteLine("Impossible ConfBand.  Exiting...");
                                System.Environment.Exit(-1);
                            }

                            double rand = r.NextDouble();
                            //Console.WriteLine("random value:" + rand);
                            //Console.WriteLine(mitigationMapDataObjectList[mitigationMapDataIndex].mitigations[i]);

                            if( mitValue >= rand)
                            {
                                //Console.WriteLine("blocked");

                                if (evasionShield >= r.NextDouble())
                                {
                                    tempEvent.savedByShield = true;
                                    continue;
                                }
                                if(System.Enum.IsDefined(typeof(bonusStage),tempEvent.currentStage.ToString()))
                                {
                                    tempEvent.softBlockedByList.Add(mitigationMapDataObjectList[mitigationMapDataIndex].mitigations[i]);
                                    tempEvent.softBlockedByScoreList.Add(1.0/agentsRemaining);
                                    tempEvent.wasSoftBlocked = true;
                                }
                                else
                                {
                                    tempEvent.blockedByList.Add(mitigationMapDataObjectList[mitigationMapDataIndex].mitigations[i]);
                                    tempEvent.blockedByScoreList.Add(1.0/agentsRemaining);
                                    tempEvent.wasBlocked = true;
                                }
                            }
                        }
                    }
                    if(!tempEvent.wasBlocked && !tempEvent.wasSoftBlocked)
                    {
                        tempEvent.successScore = (float)1.0f/agentsRemaining;
                    }
                break;
                default:
                break;
            }

            return tempEvent;
        }
        //Need to update
        public void LoadMonitoredSources()
        {
            string path = @"Data/monitored" + "_" + myEnvironment + ".csv";
            using(var reader = new StreamReader(path))
            {
                int i = 0;
                while(!reader.EndOfStream)
                {
                    i++;
                    var line = reader.ReadLine();
                    var values = line.Split(',');
                    if(i > 1)
                    {
                        if(values[0] == setDataSource)
                        {
                            values[1] = ValueData;
                        }
                        sourceList.Add(new Source(values[0],Single.Parse(values[1].Split(";")[0]),Single.Parse(values[1].Split(";")[1])));
                        if(Single.Parse(values[1].Split(";")[1]) > 0)
                        {
                            monitoredSources.Add(values[0]);
                        }
                    }
                }
            }
        }
        //Need to update
        public void LoadDetectionSources()
        {
            using(var reader = new StreamReader(@"Data/data_source.csv"))
            {
                int i = 0;
                int k = 0;
                int index = 0;
                string tempStage;
                while(!reader.EndOfStream)
                {
                    i++;
                    var line = reader.ReadLine();
                    var values = line.Split(',');
                    if(values[0].Contains("TA") || i==1)
                    {
                        if(i==1)
                        {
                            continue;
                        }
                        else
                        {
                            k++;
                        }
                    }
                    else
                    {
                        tempStage = (((stage)(k-1)).ToString() + "-"); 
                        //Console.WriteLine(tempStage + values[1]);
                        sourceMapDataObjectList.Add(new SourceMapData(tempStage+values[1],values[0],index,(stage)k-1));
                        for (int j=2;j<values.Length;j++)
                        {
                            if(!string.IsNullOrEmpty(values[j]))
                            {
                                sourceMapDataObjectList[index].sources.Add(values[j]);
                                if(monitoredSources.Contains(values[j]))
                                {
                                    sourceMapDataObjectList[index].isMonitored = true;
                                }
                            }
                        }
                        index++;
                    }
                }
            }

        } 

        public void LoadDeployedMitigations()
        {
            string path = @"Data/mitigations" + "_" + myEnvironment + ".csv";
            using(var reader = new StreamReader(path))
            {
                int i = 0;
                while(!reader.EndOfStream)
                {
                    i++;
                    var line = reader.ReadLine();
                    var values = line.Split(',');
                    if(i > 1)
                    {
                        if(values[1] == setMitigation)
                        {
                            values[3] = valueMit;
                        }
                        //Console.WriteLine("Hello?");
                        //Console.WriteLine(values[0] + " " + values[1] + " " + values[3]);
                        mitigationList.Add(new Mitigation(values[0],values[1],Single.Parse(values[3].Split(";")[0]),Single.Parse(values[3].Split(";")[1])));
                    }
                }
            }
        }

        public void LoadMitigationSources()
        {
            using(var reader = new StreamReader(@"Data/mitigation_source.csv"))
            {
                int i = 0;
                int k = 0;
                int index = 0;
                string tempStage;
                while(!reader.EndOfStream)
                {
                    i++;
                    var line = reader.ReadLine();
                    var values = line.Split(',');
                    if(values[0].Contains("TA") || i==1)
                    {
                        if(i==1)
                        {
                            continue;
                        }
                        else
                        {
                            k++;
                        }
                    }
                    else
                    {
                        tempStage = (((stage)(k-1)).ToString() + "-"); 
                        mitigationMapDataObjectList.Add(new MitigationMapData(tempStage+values[1],values[0],index,(stage)k-1));
                        for (int j=2;j<values.Length;j++)
                        {
                            if(!string.IsNullOrEmpty(values[j]))
                            {
                                mitigationMapDataObjectList[index].mitigations.Add(values[j]);
                                if(mitigationList[MitigationNameToIndexValue(values[j])].high > 0)
                                {
                                    mitigationMapDataObjectList[index].isMitigated = true;
                                }
                            }
                        }
                        index++;
                    }
                }
            }

        }


        public void LoadTTP()
        {
            using(var reader = new StreamReader(@"Data/TTP.csv"))
            {
                int i = 0;
                int k = 1;
                while (!reader.EndOfStream)
                {
                    i++;
                    var line = reader.ReadLine();
                    var values = line.Split(',');
                    //If row contains TA skip as this is a separator line.
                    if(values[0].Contains("TA") || i==1)
                    {
                        if(i==1)
                        {
                            for(int j=4;j<values.Length;j++)
                            {
                                controlsList.Add(values[j]);
                                if(values[j][0] == 'B')
                                {
                                    controlObjectList.Add(new Control(values[j]));
                                }
                            }
                        }
                        else
                        {
                            k++;
                            //Console.WriteLine((i-k).ToString() + " " + values[1]);
                            vertToCount.Add(values[1],(i-k));
                            verticalList.Add(values[1]);
                        }
                    }
                    else
                    {
                        tempStage = (((stage)(k-2)).ToString() + "-"); 

                        TTPIDList.Add(values[0]);
                        TTPNameList.Add(tempStage+values[1]);
                        TTPGroupCountList.Add(Int32.Parse(values[2]));
                        TTPSoftwareCountList.Add(Int32.Parse(values[3]));
                        countTTPByStage[k-2]++;
                        switch (k)
                        {
                                //Create a List for each Mitre Vertical that contains the name of a TTP multiple times (# of times = # groups that use the technique)
                                //This will allow one to randomly grab a name from this list with the proper distribution of technique popularity
                            case 2:
                                initialAccessList.Add(tempStage+values[1]);
                                groupWeightedInitialAccessList.AddRange(Enumerable.Repeat(tempStage+values[1], Int32.Parse(values[2])));
                                softwareWeightedInitialAccessList.AddRange(Enumerable.Repeat(tempStage+values[1], Int32.Parse(values[3])));
                                break;
                            case 3:
                                executionList.Add(tempStage+values[1]);
                                groupWeightedExecutionList.AddRange(Enumerable.Repeat(tempStage+values[1], Int32.Parse(values[2])));
                                softwareWeightedExecutionList.AddRange(Enumerable.Repeat(tempStage+values[1], Int32.Parse(values[3])));
                                break;
                            case 4:
                                persistenceList.Add(values[1]);
                                groupWeightedPersistenceList.AddRange(Enumerable.Repeat(tempStage+values[1], Int32.Parse(values[2])));
                                softwareWeightedPersistenceList.AddRange(Enumerable.Repeat(tempStage+values[1], Int32.Parse(values[3])));
                                break;
                            case 5:
                                privilegeEscalationList.Add(values[1]);
                                groupWeightedPrivilegeEscalationList.AddRange(Enumerable.Repeat(tempStage+values[1], Int32.Parse(values[2])));
                                softwareWeightedPrivilegeEscalationList.AddRange(Enumerable.Repeat(tempStage+values[1], Int32.Parse(values[3])));
                                break;
                            case 6:
                                defenseEvasionList.Add(values[1]);
                                groupWeightedDefenseEvasionList.AddRange(Enumerable.Repeat(tempStage+values[1], Int32.Parse(values[2])));
                                softwareWeightedDefenseEvasionList.AddRange(Enumerable.Repeat(tempStage+values[1], Int32.Parse(values[3])));
                                break;
                            case 7:
                                credentialAccessList.Add(values[1]);
                                groupWeightedCredentialAccessList.AddRange(Enumerable.Repeat(tempStage+values[1], Int32.Parse(values[2])));
                                softwareWeightedCredentialAccessList.AddRange(Enumerable.Repeat(tempStage+values[1], Int32.Parse(values[3])));
                                break;                           
                            case 8:
                                lateralMovementList.Add(values[1]);
                                groupWeightedLateralMovementList.AddRange(Enumerable.Repeat(tempStage+values[1], Int32.Parse(values[2])));
                                softwareWeightedLateralMovementList.AddRange(Enumerable.Repeat(tempStage+values[1], Int32.Parse(values[3])));
                                break;
                            case 9:
                                collectionList.Add(values[1]);
                                groupWeightedCollectionList.AddRange(Enumerable.Repeat(tempStage+values[1], Int32.Parse(values[2])));
                                softwareWeightedCollectionList.AddRange(Enumerable.Repeat(tempStage+values[1], Int32.Parse(values[3])));
                                break;
                            case 10:
                                exfiltrationList.Add(values[1]);
                                groupWeightedExfiltrationList.AddRange(Enumerable.Repeat(tempStage+values[1], Int32.Parse(values[2])));
                                softwareWeightedExfiltrationList.AddRange(Enumerable.Repeat(tempStage+values[1], Int32.Parse(values[3])));
                                break;
                            default:
                                Console.WriteLine(k.ToString() + "Overflow of Mitre Verticals Mitre.cs.  Check TTP.csv file.");
                                break;
                        }

                        for(int l=4;l<values.Length;l++)
                        {
                            if(i<3)
                            {
                                break;
                            }
                            if(String.IsNullOrEmpty(values[l]))
                            {

                                values[l]="0";
                            }
                            if(l%2==0)
                            {
                                controlObjectList[l/2-2].blockValueList.Add(Single.Parse(values[l]));
                            }
                            else
                            {
                                //Console.WriteLine(values[l]);
                                controlObjectList[l/2-2].detectValueList.Add(Single.Parse(values[l]));
                            }
                        }
                    }
                }   
            }

            
            for(int i=0;i<TTPGroupCountList.Count;i++)
            {
                //Console.WriteLine(softwareWeightedInitialAccessList[i]);
                //Console.WriteLine(i.ToString() + " " + TTPSoftwareCountList[i]);
                //Console.WriteLine(i.ToString() + " " + controlObjectList[i].tool);
                //Console.WriteLine(i.ToString() + " " + controlObjectList[i].blockValueList[10]);
                //Console.WriteLine(i.ToString() + " " + controlObjectList[i].detectValueList[10]);
            }
            
        }
    }
}