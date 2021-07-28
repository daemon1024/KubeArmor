#!/bin/bash

TEST_HOME=`dirname $(realpath "$0")`
CRD_HOME=`dirname $(realpath "$0")`/../deployments/CRD
ARMOR_HOME=`dirname $(realpath "$0")`/../KubeArmor

ARMOR_OPTIONS=$@

ARMOR_MSG=/tmp/kubearmor.msg
ARMOR_LOG=/tmp/kubearmor.log
TEST_LOG=/tmp/kubearmor.test

APPARMOR=0
cat /sys/kernel/security/lsm | grep apparmor > /dev/null 2>&1
if [ $? == 0 ]; then
    APPARMOR=1
fi

RED='\033[0;31m'
GREEN='\033[0;32m'
ORANGE='\033[0;33m'
BLUE='\033[0;34m'
MAGENTA='\033[0;35m'
NC='\033[0m'

## == Functions == ##

function start_and_wait_for_kubearmor_initialization() {
    cd $CRD_HOME

    kubectl apply -f .
    if [ $? != 0 ]; then
        echo -e "${RED}[FAIL] Failed to apply $1${NC}"
        exit 1
    fi

    PROXY=$(ps -ef | grep "kubectl proxy" | wc -l)
    if [ $PROXY != 2 ]; then
        echo -e "${RED}[FAIL] Proxy is not running${NC}"
        exit 1
    fi

    cd $ARMOR_HOME

    echo "Options: -logPath=$ARMOR_LOG $ARMOR_OPTIONS"
    sudo -E ./kubearmor -logPath=$ARMOR_LOG $ARMOR_OPTIONS > $ARMOR_MSG &

    for (( ; ; ))
    do
        grep "Initialized KubeArmor" $ARMOR_MSG &> /dev/null
        if [ $? == 0 ]; then
            break
        fi

        sleep 1
    done
}

function stop_and_wait_for_kubearmor_termination() {
    ps -e | grep kubearmor | awk '{print $1}' | xargs -I {} sudo kill {}

    for (( ; ; ))
    do
        ps -e | grep kubearmor &> /dev/null
        if [ $? != 0 ]; then
            break
        fi

        sleep 1
    done
}

function apply_and_wait_for_microservice_creation() {
    cd $TEST_HOME/microservices/$1

    kubectl apply -f .
    if [ $? != 0 ]; then
        echo -e "${RED}[FAIL] Failed to apply $1${NC}"
        res_microservice=1
        return
    fi

    for (( ; ; ))
    do
        RAW=$(kubectl get pods -n $1 | wc -l)

        ALL=`expr $RAW - 1`
        READY=`kubectl get pods -n $1 | grep Running | wc -l`

        if [ $ALL == $READY ]; then
            break
        fi

        sleep 1
    done
}

function delete_and_wait_for_microserivce_deletion() {
    cd $TEST_HOME/microservices/$1

    kubectl delete -f .
    if [ $? != 0 ]; then
        echo -e "${RED}[FAIL] Failed to delete $1${NC}"
        res_delete=1
    fi
}

function should_not_find_any_log() {
    echo -e "${GREEN}[INFO] Finding the corresponding log${NC}"

    sleep 3

    audit_log=$(grep -E "$1.*Policy.*$2.*$3.*$4" $ARMOR_LOG | grep -v Passed)
    if [ $? == 0 ]; then
        sleep 10

        audit_log=$(grep -E "$1.*Policy.*$2.*$3.*$4" $ARMOR_LOG | grep -v Passed)
        if [ $? == 0 ]; then
            echo $audit_log
            echo -e "${RED}[FAIL] Found the log from logs${NC}"
            res_cmd=1
        else
            audit_log="<No Log>"
            echo "[INFO] Found no log from logs"
        fi
    else
        audit_log="<No Log>"
        echo "[INFO] Found no log from logs"
    fi
}

function should_find_passed_log() {
    echo -e "${GREEN}[INFO] Finding the corresponding log${NC}"

    sleep 3

    audit_log=$(grep -E "$1.*Policy.*$2.*$3.*$4" $ARMOR_LOG | grep Passed)
    if [ $? != 0 ]; then
        sleep 10

        audit_log=$(grep -E "$1.*Policy.*$2.*$3.*$4" $ARMOR_LOG | grep Passed)
        if [ $? != 0 ]; then
            audit_log="<No Log>"
            echo -e "${RED}[FAIL] Failed to find the log from logs${NC}"
            res_cmd=1
        else
            echo $audit_log
            echo "[INFO] Found the log from logs"
        fi
    else
        echo $audit_log
        echo "[INFO] Found the log from logs"
    fi
}

function should_find_blocked_log() {
    echo -e "${GREEN}[INFO] Finding the corresponding log${NC}"

    sleep 3

    match_type="MatchedPolicy"
    if [[ $5 -eq 1 ]]; then
        match_type="MatchedNativePolicy" 
    fi

    audit_log=$(grep -E "$1.*Policy.*$2.*$3.*$4" $ARMOR_LOG | grep -v Passed)
    if [ $? != 0 ]; then
        sleep 10

        audit_log=$(grep -E "$1.*Policy.*$2.*$3.*$4" $ARMOR_LOG | grep -v Passed)
        if [ $? != 0 ]; then
            audit_log="<No Log>"
            echo -e "${RED}[FAIL] Failed to find the log from logs${NC}"
            res_cmd=1
        else
            echo $audit_log
            echo "[INFO] Found the log from logs"
        fi
    else
        echo $audit_log
        echo "[INFO] Found the log from logs"
    fi
}

function run_test_scenario() {
    cd $1

    YAML_FILE=$(ls *.yaml)
    policy_type=$(echo $YAML_FILE | awk '{split($0,a,"-"); print a[1]}')
    
    NATIVE=0
    if [[ $policy_type == "np" ]]; then
        # skip a policy with a native profile unless AppArmor is enabled
        if [ $APPARMOR == 0 ]; then
            return
        fi
        NATIVE=1
    fi

    echo -e "${GREEN}[INFO] Applying $YAML_FILE into $2${NC}"
    kubectl apply -n $2 -f $YAML_FILE
    if [ $? != 0 ]; then
        echo -e "${RED}[FAIL] Failed to apply $YAML_FILE into $2${NC}"
        res_case=1
        return
    fi
    echo "[INFO] Applied $YAML_FILE into $2"

    sleep 3
    cmd_count=0

    for cmd in $(ls cmd*)
    do
        cmd_count=$((cmd_count+1))

        SOURCE=$(cat $cmd | grep "^source" | awk '{print $2}')
        POD=$(kubectl get pods -n $2 | grep $SOURCE | awk '{print $1}')

        CMD=$(cat $cmd | grep "^cmd" | cut -d' ' -f2-)
        RESULT=$(cat $cmd | grep "^result" | awk '{print $2}')

        OP=$(cat $cmd | grep "^operation" | awk '{print $2}')
        COND=$(cat $cmd | grep "^condition" | cut -d' ' -f2-)
        ACTION=$(cat $cmd | grep "^action" | awk '{print $2}')

        # if AppArmor is not enabled
        if [ $APPARMOR == 0 ]; then
            # replace Block with Audit
            if [ "$ACTION" == "Block" ]; then
                if [ "$RESULT" == "failed" ]; then
                    ACTION="Audit"
                    RESULT="passed"
                fi
            # replace Allow with "failed" to Audit with "passed"
            elif [ "$ACTION" == "Allow" ]; then
                if [ "$RESULT" == "failed" ]; then
                    ACTION="Audit"
                    RESULT="passed"
                fi
            fi
        fi

        res_cmd=0
        audit_log=""
        actual_res="passed"

        echo -e "${GREEN}[INFO] Running \"$CMD\"${NC}"
        kubectl exec -n $2 -it $POD -- bash -c "$CMD"
        if [ $? != 0 ]; then
            actual_res="failed"
        fi

        if [ "$ACTION" == "Allow" ]; then
            if [ "$RESULT" == "passed" ]; then
                echo "[INFO] $ACTION action, and the command should be passed"
                should_not_find_any_log $POD $OP $COND $ACTION
            else
                echo "[INFO] $ACTION action, but the command should be failed"
                should_find_blocked_log $POD $OP $COND $ACTION $NATIVE
            fi
        elif [ "$ACTION" == "Audit" ] || [ "$ACTION" == "AllowWithAudit" ]; then
            if [ "$RESULT" == "passed" ]; then
                echo "[INFO] $ACTION action, and the command should be passed"
                should_find_passed_log $POD $OP $COND $ACTION
            else
                echo "[INFO] $ACTION action, but the command should be failed"
                should_find_blocked_log $POD $OP $COND $ACTION $NATIVE
            fi
        elif [ "$ACTION" == "Block" ] || [ "$ACTION" == "BlockWithAudit" ]; then
            if [ "$RESULT" == "passed" ]; then
                echo "[INFO] $ACTION action, but the command should be passed"
                should_not_find_any_log $POD $OP $COND $ACTION
            else
                echo "[INFO] $ACTION action, and the command should be failed"
                should_find_blocked_log $POD $OP $COND $ACTION $NATIVE
            fi
        fi

        if [ $res_cmd == 0 ]; then
            echo "Testcase: $3 (command #$cmd_count)" >> $TEST_LOG
            echo "Policy: $YAML_FILE" >> $TEST_LOG
            echo "Action: $ACTION" >> $TEST_LOG
            echo "Pod: $SOURCE" >> $TEST_LOG
            echo "Command: $CMD" >> $TEST_LOG
            echo "Result: $RESULT (expected) / $actual_res (actual)" >> $TEST_LOG
            echo "Log:" >> $TEST_LOG
            echo $audit_log >> $TEST_LOG
            echo >> $TEST_LOG
        else
            echo "Testcase: $3 (command #$cmd_count)" >> $TEST_LOG
            echo "Policy: $YAML_FILE" >> $TEST_LOG
            echo "Action: $ACTION" >> $TEST_LOG
            echo "Pod: $SOURCE" >> $TEST_LOG
            echo "Command: $CMD" >> $TEST_LOG
            echo "Result: $RESULT (expected) / $actual_res (actual)" >> $TEST_LOG
            echo "Output:" >> $TEST_LOG
            echo ""$(kubectl exec -n $2 -it $POD -- bash -c "$CMD") >> $TEST_LOG
            echo "Log:" >> $TEST_LOG
            echo $audit_log >> $TEST_LOG
            echo >> $TEST_LOG
            res_case=1
        fi

        sleep 1
    done

    if [ $res_case != 0 ]; then
        echo -e "${RED}[FAIL] Failed $3${NC}"
        failed_testcases+=("$3")
    else
        echo -e "${BLUE}[PASS] Passed $3${NC}"
        passed_testcases+=("$3")
    fi

    echo -e "${GREEN}[INFO] Deleting $YAML_FILE from $2${NC}"
    kubectl delete -n $2 -f $YAML_FILE
    if [ $? != 0 ]; then
        echo -e "${RED}[FAIL] Failed to delete $YAML_FILE from $2${NC}"
        res_case=1
        return
    fi
    echo "[INFO] Deleted $YAML_FILE from $2"

    sleep 1
}

## == KubeArmor == ##

sudo rm -f $ARMOR_MSG $ARMOR_LOG

total_testcases=$(ls -l $TEST_HOME/scenarios | grep ^d | wc -l)

passed_testcases=()
failed_testcases=()

echo "< KubeArmor Test Report >" > $TEST_LOG
echo >> $TEST_LOG
echo "Date:" $(date "+%Y-%m-%d %H:%M:%S %Z") >> $TEST_LOG
echo "Script: $0" >> $TEST_LOG
echo >> $TEST_LOG
echo "== Testcases ==" >> $TEST_LOG
echo >> $TEST_LOG

cd $ARMOR_HOME

if [ ! -f kubearmor ]; then
    echo -e "${ORANGE}[INFO] Building KubeArmor${NC}"
    make clean; make
    echo "[INFO] Built KubeArmor"
fi

sleep 1

echo -e "${ORANGE}[INFO] Starting KubeArmor${NC}"
start_and_wait_for_kubearmor_initialization
echo "[INFO] Started KubeArmor"

## == Test Scenarios == ##

cd $TEST_HOME

res_microservice=0

for microservice in $(ls microservices)
do
    ## == ##

    echo -e "${ORANGE}[INFO] Applying $microservice${NC}"
    apply_and_wait_for_microservice_creation $microservice

    ## == ##

    if [ $res_microservice == 0 ]; then
        echo "[INFO] Applied $microservice"

        echo "[INFO] Wait for initialization (30 secs)"
        sleep 30
        echo "[INFO] Started to run testcases"

        cd $TEST_HOME/scenarios

        for testcase in $(ls -d $microservice_*)
        do
            res_case=0

            echo -e "${ORANGE}[INFO] Testing $testcase${NC}"
            run_test_scenario $TEST_HOME/scenarios/$testcase $microservice $testcase

            if [ $res_case != 0 ]; then
                echo -e "${RED}[FAIL] Failed to test $testcase${NC}"
                res_microservice=1
            else
                echo -e "${BLUE}[PASS] Successfully tested $testcase${NC}"
            fi
        done

        res_delete=0

        echo -e "${ORANGE}[INFO] Deleting $microservice${NC}"
        delete_and_wait_for_microserivce_deletion $microservice

        if [ $res_delete == 0 ]; then
            echo "[INFO] Deleted $microservice"
        fi
    fi
done

echo "== Summary ==" >> $TEST_LOG
echo >> $TEST_LOG
echo "Passed testcases: ${#passed_testcases[@]}/$total_testcases" >> $TEST_LOG
echo >> $TEST_LOG
if [ "${#passed_testcases[@]}" != "0" ]; then
    for (( i=0; i<${#passed_testcases[@]}; i++ ));
    do
        echo "${passed_testcases[$i]}" >> $TEST_LOG;
    done
fi
echo >> $TEST_LOG
echo "Failed testcases: ${#failed_testcases[@]}/$total_testcases" >> $TEST_LOG
echo >> $TEST_LOG
if [ "${#failed_testcases[@]}" != "0" ]; then
    for (( i=0; i<${#failed_testcases[@]}; i++ ));
    do
        echo "${failed_testcases[$i]}" >> $TEST_LOG;
    done
fi
echo >> $TEST_LOG

## == KubeArmor == ##

res_kubearmor=0

echo -e "${ORANGE}[INFO] Stopping KubeArmor${NC}"
stop_and_wait_for_kubearmor_termination

if [ $res_kubearmor == 0 ]; then
    echo "[INFO] Stopped KubeArmor"
fi

if [ $res_microservice != 0 ]; then
    echo -e "${RED}[FAIL] Failed to test KubeArmor${NC}"
else
    echo -e "${BLUE}[PASS] Successfully tested KubeArmor${NC}"
fi

echo "[INFO] Remove temporary logs after 10 seconds"
sleep 10
cp $ARMOR_LOG $HOME/kubearmor.log
sudo rm -f $ARMOR_MSG $ARMOR_LOG
echo "[INFO] Removed the temporary logs"

if [ $res_microservice != 0 ]; then
    exit 1
else
    exit 0
fi
