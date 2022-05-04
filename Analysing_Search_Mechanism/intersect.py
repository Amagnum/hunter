import matplotlib.pyplot as plt

# Dynamic Programming implementation of LCS problem

# f2 = open("/content/hunter/Job_analysing_system_calls/Static_analysis/virus/virus/virus.sc", "r")
# f1 = open("/content/hunter/Job_analysing_system_calls/Static_analysis/skeksi/skeksi/skeksi.sc", "r")
# f3 = open("/content/hunter/Job_analysing_system_calls/Dynamic_analysis/Virus/main_disassembly_intel_extracted.txt", "r")

f1 = open("./Skeksi/search_skeksi_strace.txt.sc", "r")
f2 = open("./Virus/search_virus_strace.txt.sc", "r")
f3 = open("../Job_analysing_system_calls/Dynamic_analysis/Virus/main_disassembly_intel_extracted.txt", "r")
X = f1.readlines()
Y = f2.readlines()
Z = f3.readlines()
f1.close()
f2.close()
f3.close()

def generate_rank(X, r):
    mX = []
    n = len(X)
    for i in range(r-1,n):
      mX.append(''.join(X[i-r+1:i+1])+'.')
    return mX

def ploty(x1, x2, m, n):
    if(len(x1)>len(x2)): 
      return ploty(x2, x1, n, m)

    y1 = [2]*len(x1)
    y2 = [4]*len(x2)
    
    plt.figure(figsize=(120,16))
    # plt.scatter(x1, y1, color= "green",
    #             marker= ".", s=100)
    # plt.scatter(x2, y2, color= "red",
    #             marker= ".", s=100)
    print(x2[-1])
    scale_fac=n/m
    print(scale_fac)
    for i in range(len(x1)):
      plt.plot([x2[i],x1[i]*scale_fac], [4,2], color='green', linestyle='solid', linewidth = 3,
         marker='.', markerfacecolor='blue', markersize=6)

    plt.xlabel('x - axis')
    plt.ylabel('y - axis')
    plt.title('My scatter plot!')
    plt.axis([-1, max((m),(n)), -1, 10])
    plt.show()

def markMatch(X, com):
    comLen = len(com)
    m = len(X)
    colored1 = []
    j=0
    for i in range(m):
      if j<comLen and X[i][:-1] == com[j]:
        colored1.append(i)
        j+=1
    return colored1

def lcs(X, Y, m, n):
    L = [[0 for i in range(n+1)] for j in range(m+1)]
 
    # Following steps build L[m+1][n+1] in bottom up fashion. Note
    # that L[i][j] contains length of LCS of X[0..i-1] and Y[0..j-1]
    for i in range(m+1):
        for j in range(n+1):
            if i == 0 or j == 0:
                L[i][j] = 0
            elif X[i-1] == Y[j-1]:
                L[i][j] = L[i-1][j-1] + 1
            else:
                L[i][j] = max(L[i-1][j], L[i][j-1])
 
        # Create a string variable to store the lcs string
    lcs = ''
 
    # Start from the right-most-bottom-most corner and
    # one by one store characters in lcs[]
    i = m
    j = n
    while i > 0 and j > 0:
 
        # If current character in X[] and Y are same, then
        # current character is part of LCS
        if X[i-1] == Y[j-1]:
            lcs += X[i-1]
            i -= 1
            j -= 1
 
        # If not same, then find the larger of two and
        # go in the direction of larger value
        elif L[i-1][j] > L[i][j-1]:
            i -= 1
             
        else:
            j -= 1
 
    # We traversed the table in reverse order
    # LCS is the reverse of what we got

    common = lcs.split('.')
    common = common[::-1][1:]
    comLen = len(common)
    joined = '\n'.join(common)
    print(common)
    print(comLen) 
    # print('\n'.join(common))
    filr = open('common.txt', 'w')
    filr.write(joined)
    filr.close()
    print('File1: '+ str(comLen/m))
    print('File2: '+ str(comLen/n))

    marks1 = markMatch(X,common)
    marks2 = markMatch(Y,common)
    print(marks1)
    print(marks2)
    ploty(marks1, marks2, m, n)

RANK = 2
mX = generate_rank(X,RANK)
mY =  generate_rank(Y,RANK)
mZ =  generate_rank(Z,RANK)
m = len(mX)
n = len(mY)
o = len(mZ)
# lcs(mX, mZ , m, o)
lcs(mX, mY, m, n)
 